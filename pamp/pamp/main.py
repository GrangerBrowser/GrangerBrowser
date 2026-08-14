from __future__ import annotations

from collections import deque
import ipaddress
import json
from pathlib import Path
import shutil
import sys
import threading
import time
import traceback
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rich.console import Console
from rich.markup import escape
from rich.text import Text

from pamp.core.agents.orchestrator import run_orchestrator
from pamp.core.application_blueprint import build_application_blueprint
from pamp.core.application_route_intelligence import build_application_route_intelligence
from pamp.core.domain_analyzer import analyze_domain, normalize_domain
from pamp.core.ip_analyzer import analyze_ip
from pamp.core.mention_search import is_meaningful_query, parse_keywords, search_mentions
from pamp.core.models import ArtifactRecord, safe_filename_part, utc_now
from pamp.core.report_intelligence import build_analyst_notes, timeline_event
from pamp.core.case_store import (
    active_case_path,
    append_debug,
    append_debug_json,
    build_findings_payload,
    load_active_state,
    load_artifacts,
    reset_runtime_target_state,
    save_case_artifact,
    start_domain_case,
    update_active_state,
    update_runtime_target_state,
    write_artifacts,
    write_findings,
)
from pamp.i18n import DEFAULT_LANGUAGE, load_locale, normalize_language, translate
from pamp.report.html_exporter import export_html_report
from pamp.report.mention_search_exporter import export_mention_search_report


BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
CASE_DIR = BASE_DIR / "data" / "cases"
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = PROJECT_DIR / "output"
SUPPORTED_TARGET_TYPES = {"ip", "domain", "mentions", "mention_search"}
console = Console(color_system="auto")
LANGUAGE = DEFAULT_LANGUAGE
LOCALE = load_locale(LANGUAGE)


def main() -> None:
    CASE_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    active_state = load_active_state(DATA_DIR)
    set_language(active_state.get("language") or DEFAULT_LANGUAGE)
    if active_state.get("target_type") and active_state.get("target_type") not in SUPPORTED_TARGET_TYPES:
        active_state = reset_runtime_target_state(DATA_DIR, OUTPUT_DIR, language=LANGUAGE)
    show_startup_banner()
    artifacts: list[ArtifactRecord] = []
    while True:
        console.print()
        show_menu(active_state)
        choice = read_input(t("prompt.menu")).strip()

        try:
            if choice == "1":
                record, active_state = handle_ip()
                artifacts = [record]
                active_state = auto_export_report(artifacts, active_state)
            elif choice == "2":
                record, active_state = handle_domain()
                artifacts = [record]
            elif choice == "3":
                record, active_state = handle_mention_search()
                artifacts = _mention_report_artifacts(record)
            elif choice == "4":
                set_language("en" if LANGUAGE == "ru" else "ru")
                active_state = update_active_state(DATA_DIR, language=LANGUAGE)
                log_ok(f"{t('log.language')} {LANGUAGE.upper()}")
            elif choice == "5":
                log_secondary(t("log.exit"))
                return
            else:
                log_warn(t("log.select"))
        except KeyboardInterrupt:
            console.print()
            log_warn(t("log.cancelled"))
        except Exception as exc:
            debug_path = active_case_path(active_state) or OUTPUT_DIR
            append_debug(debug_path, f"[CLI][UNHANDLED] {type(exc).__name__}: {exc}\n{traceback.format_exc()}")
            if isinstance(exc, ValueError):
                log_error(str(exc))
            else:
                log_error(t("error.analysis_failed"))


def set_language(language: str) -> None:
    global LANGUAGE, LOCALE
    LANGUAGE = normalize_language(language)
    LOCALE = load_locale(LANGUAGE)


def t(key: str, default: Any = "") -> str:
    return translate(LOCALE, key, default)


def show_startup_banner() -> None:
    banner = """██████╗  █████╗ ███╗   ███╗██████╗
██╔══██╗██╔══██╗████╗ ████║██╔══██╗
██████╔╝███████║██╔████╔██║██████╔╝
██╔═══╝ ██╔══██║██║╚██╔╝██║██╔═══╝
██║      ██║  ██║██║ ╚═╝ ██║██║
╚═╝      ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝"""
    terminal_width = shutil.get_terminal_size(fallback=(100, 24)).columns
    console.print(center_ascii_art(banner, terminal_width), style="bold #6f1d1d")


def center_ascii_art(art: str, terminal_width: int) -> str:
    lines = art.splitlines()
    if not lines:
        return art
    max_width = max(len(line) for line in lines)
    left_padding = max((terminal_width - max_width) // 2, 0)
    padding = " " * left_padding
    return "\n".join(f"{padding}{line}" for line in lines)


class AnalysisProgress:
    def __init__(self, total_steps: int = 10, refresh_seconds: float = 12.0) -> None:
        self.total_steps = max(1, total_steps)
        self.refresh_seconds = max(2.0, refresh_seconds)
        self.started_at = time.monotonic()
        self.stage_started_at = self.started_at
        self.completed = 0
        self.label_key = "progress.preparing"
        self.durations: deque[float] = deque(maxlen=8)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._render("active")
        self._thread = threading.Thread(target=self._ticker, name="pamp-progress", daemon=True)
        self._thread.start()

    def update(self, completed: int, total: int, label_key: str, status: str = "completed") -> None:
        now = time.monotonic()
        with self._lock:
            if completed > self.completed:
                duration = now - self.stage_started_at
                if duration >= 0.25:
                    self.durations.append(duration)
                self.stage_started_at = now
            self.completed = max(self.completed, min(int(completed), int(total) or self.total_steps))
            self.total_steps = max(1, int(total) or self.total_steps)
            self.label_key = label_key
        self._render(status)
        if self.completed >= self.total_steps:
            self.stop()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=0.2)

    def _ticker(self) -> None:
        while not self._stop.wait(self.refresh_seconds):
            self._render("active")

    def _render(self, status: str) -> None:
        with self._lock:
            completed = self.completed
            total = self.total_steps
            label = t(self.label_key, self.label_key)
            elapsed = time.monotonic() - self.started_at
            eta = self._eta_seconds()
        percent = min(100, round(completed / total * 100))
        filled = min(16, round(percent / 100 * 16))
        bar = "█" * filled + "░" * (16 - filled)
        marker = "+" if status == "completed" else ">"
        eta_text = _format_clock(eta) if eta is not None else t("progress.calculating")
        console.print(
            f"[dark_red][{bar}][/dark_red] [bold]{percent:>3}%[/bold] "
            f"[{marker}] {escape(label)}  "
            f"[grey58]{escape(t('progress.elapsed'))} {_format_clock(elapsed)}  "
            f"{escape(t('progress.eta'))} {escape(eta_text)}[/grey58]"
        )

    def _eta_seconds(self) -> float | None:
        if not self.durations or self.completed >= self.total_steps:
            return 0.0 if self.completed >= self.total_steps else None
        average = sum(self.durations) / len(self.durations)
        current_elapsed = time.monotonic() - self.stage_started_at
        current_remaining = max(0.0, average - current_elapsed)
        remaining_after_current = max(0, self.total_steps - self.completed - 1)
        return current_remaining + average * remaining_after_current


def _format_clock(seconds: float | None) -> str:
    total = max(0, int(seconds or 0))
    return f"{total // 60:02d}:{total % 60:02d}"


def show_menu(active_state: dict[str, Any] | None = None) -> None:
    if active_state:
        target = active_state.get("target") or ""
        target_type = active_state.get("target_type") or ""
        case_file = active_state.get("case_file") or ""
        report_path = active_state.get("report_path") or ""
        data_line(menu_label("last_target"), target or menu_none())
        data_line(menu_label("target_type"), display_target_type(target_type) if target_type else menu_none())
        data_line(t("field.case_file"), display_path(case_file) if case_file else menu_none())
        data_line(t("field.report_path"), display_path(report_path) if report_path else menu_none())
        console.print()
    for key, label in [
        ("1", t("menu.analyze_ip")),
        ("2", t("menu.analyze_domain")),
        ("3", t("menu.mention_search")),
        ("4", f"{t('menu.language')} ({'ENG' if LANGUAGE == 'ru' else 'RU'})"),
        ("5", t("menu.exit")),
    ]:
        line = Text()
        line.append(f"[{key}]", style="bold #7a2424")
        line.append(f" {label}", style="#d7d7d7")
        console.print(line)
    console.print()


def read_input(scope: str) -> str:
    if scope == "pamp::menu":
        return console.input("[#8a2b2b]pamp[/#8a2b2b][#4b1717]::[/#4b1717][white]menu[/white] [#8a2b2b]>[/#8a2b2b] ")
    return console.input(f"[white]{escape(scope)} > [/white]")


def handle_ip() -> tuple[ArtifactRecord, dict[str, Any]]:
    ip = read_input(t("prompt.ip")).strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {ip}") from exc
    active_state = reset_runtime_target_state(DATA_DIR, OUTPUT_DIR, language=LANGUAGE)
    log_secondary(t("log.ip_started"))
    try:
        result = analyze_ip(ip, debug_log=lambda message: append_debug(OUTPUT_DIR, message))
        log_ok(t("log.ip_done"))
    except Exception as exc:
        append_debug(OUTPUT_DIR, f"[IP][ANALYSIS] {type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        result = _partial_ip_result(ip, exc)
        log_warn(t("error.analysis_partial"))
    for error in result.get("errors") or []:
        append_debug(OUTPUT_DIR, f"[IP][SOURCE] {error}")
    print_summary(
        t("summary.ip"),
        [
            (t("field.ip"), result.get("ip")),
            (t("field.country"), result.get("country")),
            (t("field.city"), result.get("city")),
            (t("field.asn"), result.get("asn")),
            (t("field.organization"), result.get("organization")),
            (t("field.provider"), result.get("provider")),
            (t("field.reverse_dns"), result.get("reverse_dns")),
            (t("field.hosting"), result.get("hosting_or_datacenter")),
            (t("field.proxy"), result.get("vpn_proxy_tor")),
        ],
    )
    record, case_file = save_artifact_with_path("ip", result["ip"], result, "ip_analyzer")
    active_state = update_runtime_target_state(
        DATA_DIR,
        target=result["ip"],
        target_type="ip",
        last_action="ip_analysis",
        case_file=case_file,
        current_ip=result["ip"],
        ip_data=result,
        current_artifacts=[{"type": record.type, "label": record.label, "id": record.id}],
    )
    return record, active_state


def handle_domain() -> tuple[ArtifactRecord, dict[str, Any]]:
    domain = read_input(t("prompt.target")).strip()
    if not domain:
        raise ValueError(t("error.domain_empty"))

    active_state = start_domain_case(DATA_DIR, domain, OUTPUT_DIR, language=LANGUAGE)
    case_path = Path(active_state["case_path"])
    log_secondary(t("log.domain_session"))
    data_line(t("field.target"), domain)

    result: dict[str, Any] = {}
    progress = AnalysisProgress(total_steps=10)
    progress.start()
    try:
        result = analyze_domain(
            domain,
            debug_log=lambda message: append_debug(case_path, message),
            artifact_dir=case_path,
            traffic_log=print_traffic_live,
            progress_callback=progress.update,
        )
    except Exception as exc:
        append_debug(
            case_path,
            f"{t('log.domain_failed')}\nerror={type(exc).__name__}: {exc}\n{traceback.format_exc()}",
        )
        result = _partial_domain_result(domain, exc)
        log_warn(t("error.analysis_partial"))
    finally:
        progress.stop()

    port_surface = result.get("port_surface") or {}
    port_summary = port_surface.get("summary") or {}
    if port_surface.get("status") in {"completed", "partial"}:
        log_ok(f"{t('field.open_ports')}: {port_summary.get('open_ports') or 0}")
        log_ok(f"{t('field.services_identified')}: {port_summary.get('services_identified') or 0}")
        log_ok(t("log.port_surface_completed"))
    else:
        log_warn(
            f"{t('log.port_surface_skipped')}: "
            f"{port_surface.get('skip_reason') or port_surface.get('status') or 'unavailable'}"
        )

    append_debug(case_path, _debug_modules(result))
    append_debug(case_path, _devtools_debug_text(result.get("devtools") or {}))
    append_debug(case_path, _historical_debug_text(result))
    append_debug(case_path, _reputation_debug_text(result))
    append_debug_json(case_path, "devtools intelligence debug", _devtools_debug(result.get("devtools") or {}))
    append_debug_json(case_path, "historical intelligence debug", _historical_debug(result))
    append_debug_json(case_path, "reputation intelligence debug", _reputation_debug(result))
    append_debug_json(case_path, "raw domain result", result)
    print_execution_log(result.get("execution_log") or [])

    if _is_ip_address(result.get("host") or result.get("domain") or domain):
        append_debug(case_path, f"[DOMAIN][DISCOVERY] target={result.get('domain') or domain} skipped for IP input")
        workflow = {
            "steps": [
                {"agent": "discovery_agent", "status": "skipped", "summary": {"reason": "IP input in domain analysis"}},
                {"agent": "sqli_analysis_agent", "status": "skipped", "summary": {"reason": "IP input in domain analysis"}},
            ],
            "discovery": {},
            "sqli_analysis": {},
            "domain_updates": {},
        }
        discovery = {}
        sqli_analysis = {}
        result["api_endpoints"] = result.get("api_endpoints") or []
        result["discovery"] = discovery
        result["sqli_analysis"] = sqli_analysis
        result["agent_workflow"] = workflow["steps"]
        result["crawler_agent"] = {}
        result["devtools_agent"] = {}
        result["technology_agent"] = {}
        result["execution_log"] = _append_execution_stage(result.get("execution_log") or [], "discovery_agent", "skipped for IP input")
        result["execution_log"] = _append_execution_stage(result.get("execution_log") or [], "sqli_analysis_agent", "skipped for IP input")
    else:
        workflow = run_orchestrator(
            result.get("domain") or domain,
            result,
            debug_log=lambda message: append_debug(case_path, message),
        )
        discovery = workflow.get("discovery") or {}
        sqli_analysis = workflow.get("sqli_analysis") or {}
        domain_updates = workflow.get("domain_updates") or {}
        result["api_endpoints"] = domain_updates.get("api_endpoints") or result.get("api_endpoints") or []
        result["discovery"] = discovery
        result["sqli_analysis"] = sqli_analysis
        result["agent_workflow"] = workflow.get("steps") or []
        result["crawler_agent"] = workflow.get("crawler") or {}
        result["devtools_agent"] = workflow.get("devtools") or {}
        result["technology_agent"] = workflow.get("technology") or {}
        result["execution_log"] = _append_execution_stage(
            result.get("execution_log") or [],
            "discovery_agent",
            _workflow_execution_status(
                workflow.get("steps") or [],
                "discovery_agent",
                f"{len(discovery.get('findings') or [])} interesting",
            ),
        )
        result["execution_log"] = _append_execution_stage(
            result.get("execution_log") or [],
            "sqli_analysis_agent",
            _workflow_execution_status(
                workflow.get("steps") or [],
                "sqli_analysis_agent",
                f"{len(sqli_analysis.get('findings') or [])} confirmed",
            ),
        )
    security_count = len(result.get("security_findings") or []) + len(result.get("security_signals") or [])
    result["execution_log"] = _append_execution_stage(
        result.setdefault("execution_log", []),
        "security_audit",
        f"{security_count} finding(s)",
    )
    result["analyst_timeline"] = list(result.get("analyst_timeline") or [])
    result["analyst_timeline"].append(
        timeline_event(
            "Active discovery completed" if discovery else "Active discovery skipped",
            source="discovery",
            detail=f"{len(discovery.get('findings') or [])} interesting path(s)",
        )
    )
    result["analyst_timeline"].append(
        timeline_event(
            "Security audit completed",
            source="security_audit",
            detail=f"{security_count} passive finding(s)",
        )
    )
    result["application_route_intelligence"] = _recover_module(
        "application_route_intelligence",
        lambda: build_application_route_intelligence(result),
        {"status": "failed", "summary": {}, "routes": [], "errors": ["Module failed"]},
        case_path,
        result.setdefault("execution_log", []),
    )
    route_summary = result["application_route_intelligence"].get("summary") or {}
    route_failed = result["application_route_intelligence"].get("status") == "failed"
    if not route_failed:
        result["execution_log"] = _append_execution_stage(
            result.setdefault("execution_log", []),
            "application_route_intelligence",
            f"{route_summary.get('total_routes') or 0} route(s), {route_summary.get('high_interest') or 0} high-interest",
        )
    result["analyst_timeline"].append(
        timeline_event(
            "Application Route Intelligence failed" if route_failed else "Application Route Intelligence completed",
            source="application_route_intelligence",
            detail=(
                f"{route_summary.get('total_routes') or 0} route(s), "
                f"{route_summary.get('js_recovered_routes') or 0} JS recovered, "
                f"{route_summary.get('dynamic_imports') or 0} dynamic import(s)"
            ),
        )
    )
    result["analyst_notes"] = _recover_module(
        "analyst_notes",
        lambda: build_analyst_notes(result),
        [],
        case_path,
        result.get("execution_log") or [],
    )
    if isinstance(result.get("http_surface"), dict):
        result["http_surface"]["analyst_notes"] = result["analyst_notes"]
    result["analyst_timeline"].append(
        timeline_event("HTML report prepared", source="report", detail="output/report.html")
    )
    result["application_blueprint"] = _recover_module(
        "application_blueprint",
        lambda: build_application_blueprint(result),
        {"status": "failed", "summary": {}, "nodes": [], "edges": [], "insights": []},
        case_path,
        result.get("execution_log") or [],
    )
    blueprint_summary = result["application_blueprint"].get("summary") or {}
    result["analyst_timeline"].append(
        timeline_event(
            "Application Blueprint prepared",
            source="application_blueprint",
            detail=f"{blueprint_summary.get('nodes') or 0} node(s), {blueprint_summary.get('edges') or 0} edge(s)",
        )
    )
    result["sources"] = list(result.get("sources") or [])
    for source in (
        "Pamp Orchestrator",
        "Pamp Discovery Agent",
        "Pamp Crawler Agent",
        "Pamp DevTools Agent",
        "Pamp SQLi Analysis Agent",
        "Pamp Technology Agent",
        "Pamp Report Agent",
        "Pamp Application Route Intelligence",
        "Pamp Application Blueprint",
    ):
        _append_unique(result["sources"], source)
    append_debug_json(case_path, "agent workflow", workflow)
    append_debug_json(case_path, "ffuf discovery debug", discovery.get("debug") or {})
    append_debug_json(case_path, "sqli analysis debug", sqli_analysis.get("debug") or {})
    if _is_ip_address(result.get("host") or result.get("domain") or domain):
        log_warn(t("log.discovery_skipped_ip"))
    else:
        _print_pipeline_summary(result, discovery, sqli_analysis)

    record, case_file = save_artifact_with_path("domain", result["domain"], result, "domain_analyzer")
    artifacts = [record]
    artifacts_path = write_artifacts(case_path, artifacts)
    findings_path = write_findings(case_path, build_findings_payload(result["domain"], artifacts))
    report_artifacts = load_artifacts(case_path)
    try:
        paths = export_html_report(report_artifacts, {}, OUTPUT_DIR / "report.html", language=LANGUAGE)
    except Exception as exc:
        append_debug(case_path, f"[DOMAIN][REPORT] {type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        fallback = ArtifactRecord(
            type="domain",
            label=result["domain"],
            data=_partial_domain_result(result["domain"], exc),
            source="report_recovery",
        )
        paths = export_html_report([fallback], {}, OUTPUT_DIR / "report.html", language=LANGUAGE)
        log_warn(t("error.report_partial"))
    log_ok(f"{t('field.report')}: {display_path(paths['report'])}")

    log_ok(t("log.trackers"))
    log_ok(t("log.technologies"))
    log_ok(t("log.report"))

    active_state = update_runtime_target_state(
        DATA_DIR,
        target=result["domain"],
        target_type="domain",
        last_action="domain_analysis",
        case_file=case_file,
        report_path=str(paths["report"]),
        language=LANGUAGE,
        debug_path=str(case_path / "debug.log"),
        current_domain=result["domain"],
        current_findings=result.get("security_findings") or [],
        current_artifacts=[{"type": record.type, "label": record.label, "id": record.id}],
        domain_data=result,
        current_domain_data={
            "domain": result.get("domain"),
            "http_status": (result.get("http") or {}).get("status_code"),
            "dns_records": sum(len(values) for values in (result.get("dns") or {}).values()),
        },
        decoded_artifacts=state_decoded_artifacts(result.get("decoded_classified_artifacts") or []),
        trackers=result.get("analytics_tracker_hints") or [],
        technologies=result.get("detected_technologies") or [],
        security_findings=result.get("security_findings") or [],
        sensitive_files=state_sensitive_files((result.get("sensitive_public_files") or {}).get("findings") or []),
        network_requests=[],
        emails=state_strings(result.get("emails") or []),
        phones=state_strings(result.get("phones") or []),
        endpoints=state_endpoints(result.get("api_endpoints") or []),
    )
    append_debug(case_path, f"report source file={artifacts_path}")
    append_debug(case_path, f"findings source file={findings_path}")
    append_debug(case_path, f"report output path={paths['report']}")
    append_debug(case_path, f"[state] report generated from target: {result['domain']}")
    print_domain_dossier(result, paths["report"])
    return record, active_state


def handle_mention_search() -> tuple[ArtifactRecord, dict[str, Any]]:
    target = read_input(t("prompt.mention_target", "Target domain or URL")).strip()
    keywords = read_input(t("prompt.mention_keywords", "Keyword or keywords")).strip()
    mode = read_input(
        t(
            "prompt.mention_mode",
            "Search mode [default / exact / case / fuzzy / variants / all]",
        )
    ).strip() or "default"
    if not target:
        raise ValueError(t("error.mention_target_empty"))
    if not keywords:
        raise ValueError(t("error.keywords_empty"))
    if any(not is_meaningful_query(keyword) for keyword in parse_keywords(keywords.replace("\\n", "\n"))):
        raise ValueError(t("error.mention_query_invalid"))

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    domain_record = _latest_domain_artifact(target)
    debug_log = lambda message: append_debug(OUTPUT_DIR, message)
    log_secondary(t("log.mention_search_started"))
    try:
        result = search_mentions(
            target,
            keywords.replace("\\n", "\n"),
            mode=mode,
            existing_domain_data=domain_record.data if domain_record else None,
            debug_log=debug_log,
        )
    except Exception as exc:
        append_debug(OUTPUT_DIR, f"[MENTION][FETCH] target={target} error={exc}")
        raise

    record, case_file = save_artifact_with_path(
        "mention_search",
        result["target"],
        result,
        "mention_search",
    )
    artifacts = ([domain_record] if domain_record else []) + [record]
    record.data = result
    Path(case_file).write_text(
        json.dumps(record.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    write_artifacts(OUTPUT_DIR, artifacts)
    write_findings(
        OUTPUT_DIR,
        {
            "target": result["target"],
            "generated_at": utc_now(),
            "artifact_count": len(artifacts),
            "mention_search": {
                "summary": result.get("summary") or {},
                "top_matches": result.get("top_matches") or [],
            },
        },
    )
    try:
        paths = export_mention_search_report(
            result,
            OUTPUT_DIR / "mentions_report.html",
            language=LANGUAGE,
        )
    except Exception as exc:
        append_debug(OUTPUT_DIR, f"[MENTION][REPORT] {type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        paths = export_html_report(
            artifacts,
            {},
            OUTPUT_DIR / "mentions_report.html",
            language=LANGUAGE,
        )
        log_warn(t("error.report_partial"))

    summary = result.get("summary") or {}
    print_summary(
        t("summary.mention_search"),
        [
            (t("field.target"), result.get("target")),
            (t("field.keywords"), ", ".join(result.get("keywords") or [])),
            (t("field.pages_scanned"), summary.get("pages_scanned")),
            (t("field.pages_with_matches"), summary.get("pages_with_matches")),
            (t("field.matches"), summary.get("matches")),
            (t("field.occurrences"), summary.get("total_occurrences")),
            (t("field.sections"), ", ".join((summary.get("sections") or {}).keys()) or t("value.none")),
            (t("field.report"), display_path(paths["report"])),
            (t("field.artifact"), display_path(case_file)),
        ],
    )
    top_matches = result.get("top_matches") or []
    if top_matches:
        console.print()
        log_secondary(t("log.top_pages"))
        for row in (summary.get("top_pages") or [])[:10]:
            console.print(
                f"[grey58]{escape(str(row.get('matches') or 0))}[/grey58] "
                f"{escape(str(row.get('path') or row.get('url') or ''))}"
            )

    active_state = update_runtime_target_state(
        DATA_DIR,
        target=result["target"],
        target_type="mention_search",
        last_action="mention_search",
        case_file=case_file,
        report_path=str(paths["report"]),
        language=LANGUAGE,
        debug_path=str(OUTPUT_DIR / "debug.log"),
        current_artifacts=[
            {"type": artifact.type, "label": artifact.label, "id": artifact.id}
            for artifact in artifacts
        ],
        mention_data=result,
    )
    append_debug(
        OUTPUT_DIR,
        f"[MENTION][REPORT] target={result['target']} status=ok path={paths['report']}",
    )
    return record, active_state


def auto_export_report(
    artifacts: list[ArtifactRecord],
    active_state: dict[str, Any],
) -> dict[str, Any]:
    try:
        paths = export_html_report(artifacts, {}, OUTPUT_DIR / "report.html", language=LANGUAGE)
    except Exception as exc:
        append_debug(OUTPUT_DIR, f"[REPORT][AUTO] {type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        artifact = artifacts[-1] if artifacts else None
        if artifact and artifact.type == "ip":
            fallback_data = _partial_ip_result(artifact.label, exc)
            fallback_type = "ip"
        else:
            label = artifact.label if artifact else "unknown"
            fallback_data = _partial_domain_result(label, exc)
            fallback_type = "domain"
        fallback = ArtifactRecord(
            type=fallback_type,
            label=artifact.label if artifact else "unknown",
            data=fallback_data,
            source="report_recovery",
        )
        paths = export_html_report([fallback], {}, OUTPUT_DIR / "report.html", language=LANGUAGE)
        log_warn(t("error.report_partial"))
    case_path = active_case_path(active_state)
    if case_path:
        artifacts_path = write_artifacts(case_path, artifacts)
        target = active_state.get("target") or (artifacts[-1].label if artifacts else "")
        findings_path = write_findings(case_path, build_findings_payload(target, artifacts))
        report_data = paths.get("report_data") if isinstance(paths.get("report_data"), dict) else {}
        if active_state.get("target_type") == "ip":
            ip_data = artifacts[-1].data if artifacts else {}
            if not ip_data:
                append_debug(case_path, "[ip-report] ERROR: ip_data is empty before export")
            append_debug(case_path, f"[ip-report] target_type={active_state.get('target_type')}")
            append_debug(case_path, f"[ip-report] ip_data keys: {', '.join(sorted(ip_data.keys())) if ip_data else 'none'}")
            append_debug(case_path, f"[ip-report] report_data keys: {', '.join(sorted(report_data.keys())) if report_data else 'none'}")
            append_debug(case_path, f"[ip-report] template mode: {report_data.get('target_type') or 'none'}")
        append_debug(case_path, f"report source file={artifacts_path}")
        append_debug(case_path, f"findings source file={findings_path}")
        append_debug(case_path, f"auto report output path={paths['report']}")
        append_debug(case_path, f"[state] report generated from target: {target}")
        if active_state.get("target_type") == "ip":
            append_debug(case_path, "[ip-report] output/report.html written")
    active_state = update_active_state(DATA_DIR, report_path=str(paths["report"]), language=LANGUAGE)
    log_ok(f"{t('log.report_updated')} {display_path(paths['report'])}")
    return active_state


def print_summary(title: str, rows: list[tuple[str, Any]]) -> None:
    console.print()
    log_secondary(title)
    for key, value in rows:
        formatted = format_value(value)
        if formatted:
            data_line(key, formatted)


def print_execution_log(rows: list[dict[str, str]]) -> None:
    if not rows:
        return
    for row in rows:
        stage = row.get("stage", "").strip() or "module"
        status = row.get("status", "").strip()
        lowered = status.lower()
        label = _stage_label(stage)
        if "timeout" in lowered:
            log_warn(f"{label}: timeout")
        elif "failed" in lowered or "error" in lowered or "unavailable" in lowered:
            log_warn(f"{label}: {t('status.failed')}")
        elif "partial" in lowered:
            log_warn(f"{label}: {status}")
        elif "skip" in lowered:
            log_warn(f"{label}: {status}")
        else:
            log_ok(f"{label}: {status or t('status.done')}")


def _stage_label(stage: str) -> str:
    return {
        "dns": t("stage.dns"),
        "rdap": t("stage.rdap"),
        "tls": t("stage.tls"),
        "http": t("stage.http"),
        "devtools": t("stage.devtools"),
        "sensitive_files": t("stage.sensitive_files"),
        "historical_intelligence": t("stage.historical"),
        "reputation_intelligence": t("stage.reputation"),
    }.get(stage, stage.replace("_", " ").strip().title() or t("stage.generic"))


def _debug_modules(result: dict[str, Any]) -> str:
    completed = []
    failed = []
    for row in result.get("execution_log") or []:
        stage = row.get("stage", "")
        status = row.get("status", "")
        if "failed" in status.lower():
            failed.append(f"{stage}:{status}")
        else:
            completed.append(f"{stage}:{status}")
    errors = result.get("errors") or []
    return "\n".join(
        [
            f"modules completed={'; '.join(completed) if completed else 'none'}",
            f"modules failed={'; '.join(failed) if failed else 'none'}",
            f"errors={len(errors)}",
        ]
    )


def _historical_debug(result: dict[str, Any]) -> dict[str, Any]:
    historical = result.get("historical_intelligence") or {}
    debug = historical.get("debug") or {}
    return {
        "wayback_request_url": debug.get("wayback_request_url") or "",
        "wayback_count": debug.get("wayback_count") or 0,
        "crtsh_request_url": debug.get("crtsh_request_url") or "",
        "crtsh_fallback_request_url": debug.get("crtsh_fallback_request_url") or "",
        "crtsh_certificate_count": debug.get("crtsh_certificate_count") or 0,
        "crtsh_subdomain_count": debug.get("crtsh_subdomain_count") or 0,
        "unavailable_sources": historical.get("unavailable_sources") or [],
        "errors": historical.get("errors") or [],
    }


def _historical_debug_text(result: dict[str, Any]) -> str:
    historical = result.get("historical_intelligence") or {}
    debug = historical.get("debug") or {}
    return "\n".join(
        [
            f"Wayback request URL={debug.get('wayback_request_url') or ''}",
            f"Wayback count={debug.get('wayback_count') or 0}",
            f"crt.sh request URL={debug.get('crtsh_request_url') or ''}",
            f"crt.sh fallback request URL={debug.get('crtsh_fallback_request_url') or ''}",
            f"certificate count={debug.get('crtsh_certificate_count') or 0}",
            f"subdomain count={debug.get('crtsh_subdomain_count') or 0}",
            f"historical errors={len(historical.get('errors') or [])}",
            f"full errors={json.dumps(historical.get('errors') or [], ensure_ascii=False)}",
        ]
    )


def _devtools_debug_text(devtools: dict[str, Any]) -> str:
    intelligence = devtools.get("devtools_intelligence") or {}
    summary = intelligence.get("summary") or {}
    storage = devtools.get("storage_intelligence") or {}
    storage_count = sum(len(storage.get(key) or []) for key in ("localStorage", "sessionStorage", "indexedDB", "cacheStorage"))
    return "\n".join(
        [
            f"[devtools] captured requests={summary.get('network_requests') or len(devtools.get('network_requests') or [])}",
            f"[devtools] detected api={summary.get('api_endpoints') or len(devtools.get('api_endpoints') or [])}",
            f"[devtools] graphql={summary.get('graphql') or len(devtools.get('graphql_intelligence') or [])}",
            f"[devtools] websocket={summary.get('websockets') or len(devtools.get('websocket_intelligence') or [])}",
            f"[devtools] storage objects={summary.get('storage_objects') or storage_count}",
            f"[devtools] cookies={summary.get('cookies') or len(devtools.get('cookie_intelligence') or [])}",
            f"[devtools] js intelligence files={summary.get('javascript_files') or len((devtools.get('javascript_intelligence') or {}).get('files') or [])}",
            f"[devtools] js intelligence findings={len((devtools.get('javascript_intelligence') or {}).get('findings') or [])}",
            f"[devtools] third party services={summary.get('third_party_services') or len(devtools.get('third_party_services') or [])}",
            f"[devtools] top findings={summary.get('top_findings') or len(devtools.get('interesting_findings') or [])}",
            f"[devtools] errors={len(devtools.get('errors') or [])}",
            f"[devtools] duration_ms={devtools.get('duration_ms') or (devtools.get('statistics') or {}).get('duration_ms') or 0}",
        ]
    )


def _devtools_debug(devtools: dict[str, Any]) -> dict[str, Any]:
    network = (devtools.get("network_intelligence") or {}).get("requests") or devtools.get("network_requests") or []
    api = (devtools.get("api_intelligence") or {}).get("endpoints") or devtools.get("api_endpoints") or []
    javascript = devtools.get("javascript_intelligence") or {}
    storage = devtools.get("storage_intelligence") or {}
    return {
        "summary": (devtools.get("devtools_intelligence") or {}).get("summary") or {},
        "network_requests": [
            {
                "method": row.get("method"),
                "status": row.get("status"),
                "resource_type": row.get("resource_type"),
                "url": row.get("url"),
                "content_type": row.get("content_type"),
                "response_size": row.get("response_size"),
                "duration": row.get("duration"),
            }
            for row in network[:120]
        ],
        "api": api[:120],
        "graphql": (devtools.get("graphql_intelligence") or [])[:80],
        "websocket": (devtools.get("websocket_intelligence") or [])[:80],
        "storage": {
            key: (storage.get(key) or [])[:80]
            for key in ("localStorage", "sessionStorage", "indexedDB", "cacheStorage")
        },
        "cookies": (devtools.get("cookie_intelligence") or [])[:120],
        "javascript": {
            "files": (javascript.get("files") or [])[:120],
            "findings": (javascript.get("findings") or [])[:120],
            "domains": (javascript.get("domains") or [])[:120],
            "subdomains": (javascript.get("subdomains") or [])[:120],
            "routes": (javascript.get("routes") or [])[:120],
        },
        "third_party_services": (devtools.get("third_party_services") or [])[:120],
        "interesting_findings": (devtools.get("interesting_findings") or [])[:20],
        "errors": devtools.get("errors") or [],
    }


def _reputation_debug(result: dict[str, Any]) -> dict[str, Any]:
    reputation = result.get("reputation_intelligence") or {}
    debug = reputation.get("debug") or {}
    return {
        "feeds_checked": debug.get("feeds_checked") or [],
        "feeds_unavailable": debug.get("feeds_unavailable") or [],
        "indicator_counts": debug.get("indicator_counts") or {},
        "request_count": len(debug.get("requests") or []),
        "requests": (debug.get("requests") or [])[:80],
        "errors": reputation.get("errors") or [],
    }


def _reputation_debug_text(result: dict[str, Any]) -> str:
    reputation = result.get("reputation_intelligence") or {}
    debug = reputation.get("debug") or {}
    checked = ", ".join(debug.get("feeds_checked") or [])
    unavailable = ", ".join(
        f"{row.get('source')}: {row.get('error')}"
        for row in (debug.get("feeds_unavailable") or [])
    )
    return "\n".join(
        [
            f"feeds checked={checked}",
            f"feeds unavailable={unavailable}",
            f"reputation indicator counts={json.dumps(debug.get('indicator_counts') or {}, ensure_ascii=False)}",
            f"reputation request count={len(debug.get('requests') or [])}",
            f"reputation errors={len(reputation.get('errors') or [])}",
            f"full errors={json.dumps(reputation.get('errors') or [], ensure_ascii=False)}",
        ]
    )


def print_domain_dossier(result: dict[str, Any], report_path: Path) -> None:
    http_surface = result.get("http_surface") or {}
    signals = result.get("security_signals") or []
    interesting_paths = result.get("interesting_paths") or []
    signal_counts = {
        "info": sum(1 for item in signals if item.get("level") == "info"),
        "warn": sum(1 for item in signals if item.get("level") == "warn"),
        "high": sum(1 for item in signals if item.get("level") == "high"),
    }
    signal_text = ", ".join(f"{count} {level}" for level, count in signal_counts.items() if count) or "No security signals"
    technologies = [item.get("name") for item in (result.get("technologies") or []) if item.get("name")]
    if not technologies:
        technologies = result.get("detected_technologies") or []
    tech_text = ", ".join(str(item) for item in technologies[:8]) or "No technologies detected"
    path_text = ", ".join(str(item.get("path") or "").lstrip("/") for item in interesting_paths[:8]) or "No interesting paths"
    ips = result.get("linked_ip_addresses") or []
    asn_rows = result.get("asn_bgp") or []
    asn_text = ", ".join(
        str(row.get("asn") or row.get("name") or "").strip()
        for row in asn_rows[:4]
        if str(row.get("asn") or row.get("name") or "").strip()
    )
    redirect_text = _redirect_summary(http_surface)
    port_summary = (result.get("port_surface") or {}).get("summary") or {}
    social_summary = (result.get("social_intelligence") or {}).get("summary") or {}
    dns_ok = "ok" if any((result.get("dns") or {}).values()) else "no records"
    console.print()
    if http_surface.get("primary_url"):
        rows = [
            ("target", result.get("host") or result.get("domain")),
            ("ip", ", ".join(ips[:6]) or "No data"),
            ("asn", asn_text or "No data"),
            ("http", http_surface.get("primary_url")),
            ("status", http_surface.get("status_code")),
            ("title", http_surface.get("title") or "No data"),
            ("server", http_surface.get("server") or "No data"),
            ("Open Ports", port_summary.get("open_ports") or 0),
            ("Detected Services", port_summary.get("services_identified") or 0),
        ]
        if redirect_text:
            rows.append(("redirects", redirect_text))
        rows.extend(
            [
                ("tech", tech_text),
                ("signals", signal_text),
                ("paths", path_text),
                ("Social profiles", social_summary.get("profiles_analyzed") or len(result.get("social_profiles") or [])),
                ("Platforms", social_summary.get("platforms_found") or 0),
                ("Verified", social_summary.get("verified_profiles") or 0),
                ("Recent posts", social_summary.get("recent_posts_found") or 0),
                ("External links", social_summary.get("external_links_found") or 0),
                ("report", display_path(report_path)),
            ]
        )
        if social_summary.get("fetch_warnings"):
            rows.insert(-1, ("Social fetch warnings", social_summary.get("fetch_warnings")))
        print_summary(
            "DOMAIN ANALYSIS",
            rows,
        )
    else:
        print_summary(
            "DOMAIN ANALYSIS",
            [
                ("target", result.get("host") or result.get("domain")),
                ("dns", dns_ok),
                ("http", "no live HTTP service"),
                ("Open Ports", port_summary.get("open_ports") or 0),
                ("Detected Services", port_summary.get("services_identified") or 0),
                ("Social profiles", social_summary.get("profiles_analyzed") or len(result.get("social_profiles") or [])),
                ("errors", "see debug.log"),
                ("report", display_path(report_path)),
            ],
        )


def _redirect_summary(http_surface: dict[str, Any]) -> str:
    chain = http_surface.get("redirect_chain") or []
    if not chain:
        for probe in http_surface.get("probes") or []:
            if probe.get("redirect_chain"):
                chain = probe.get("redirect_chain") or []
                break
    if not chain:
        return ""
    urls = [str(chain[0].get("from") or "")]
    urls.extend(str(row.get("to") or "") for row in chain if row.get("to"))
    labels = []
    for url in urls:
        if "://" in url:
            labels.append(url.split("://", 1)[0])
        elif url:
            labels.append(url)
    if http_surface.get("final_url") and (not labels or labels[-1] != "final"):
        labels.append("final")
    return " -> ".join(labels)


def _is_ip_address(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


def _print_pipeline_summary(
    result: dict[str, Any],
    discovery: dict[str, Any],
    sqli_analysis: dict[str, Any],
) -> None:
    crawler = result.get("crawler_agent") or {}
    crawler_summary = crawler.get("summary") or {}
    sqli_summary = sqli_analysis.get("summary") or {}
    discovery_failed = str(discovery.get("status") or "").lower() == "failed"
    sqli_failed = str(sqli_analysis.get("status") or "").lower() == "failed"
    if discovery_failed:
        log_warn(f"{t('stage.discovery', 'Discovery')}: {t('status.failed')}")
    else:
        log_ok(t("log.discovery_completed"))
    log_ok(f"{t('field.routes_found')}: {len(discovery.get('all_results') or [])}")
    log_ok(f"{t('field.interesting_routes')}: {len(discovery.get('findings') or [])}")
    log_ok(f"{t('field.api_endpoints')}: {len(result.get('api_endpoints') or [])}")
    log_ok(f"{t('field.forms')}: {crawler_summary.get('forms') or len(((result.get('html') or {}).get('forms') or []))}")
    log_ok(f"{t('field.parameters')}: {sqli_summary.get('candidate_parameters') or 0}")
    if sqli_failed:
        log_warn(f"SQLi: {t('status.failed')}")
    else:
        log_ok(t("log.sqli_completed"))
    log_ok(f"{t('field.confirmed_signals')}: {len(sqli_analysis.get('findings') or [])}")


def format_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return t("value.yes") if value else t("value.no")
    if isinstance(value, (list, tuple, set)):
        values = list(value)
        if not values:
            return ""
        preview = ", ".join(str(item) for item in values[:8])
        suffix = f" (+{len(values) - 8})" if len(values) > 8 else ""
        return preview + suffix
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def menu_label(key: str) -> str:
    return t(f"field.{key}")


def menu_none() -> str:
    return t("value.none")


def display_target_type(target_type: str) -> str:
    key = "mentions" if target_type in {"mentions", "mention_search"} else target_type
    return t(f"target_type.{key}", target_type)


def save_artifact_with_path(
    artifact_type: str,
    label: str,
    data: dict[str, Any],
    source: str,
    case_path: Path | None = None,
) -> tuple[ArtifactRecord, Path]:
    artifact = ArtifactRecord(type=artifact_type, label=str(label), data=data, source=source)
    if case_path:
        path = save_case_artifact(case_path, artifact)
    else:
        CASE_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = utc_now().replace("+00:00", "Z").replace(":", "")
        filename = f"{timestamp}_{artifact_type}_{safe_filename_part(str(label))}.json"
        path = CASE_DIR / filename
        path.write_text(json.dumps(artifact.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    log_secondary(f"{t('log.artifact_saved')} {display_path(path)}")
    return artifact, path


def save_artifact(
    artifact_type: str,
    label: str,
    data: dict[str, Any],
    source: str,
    case_path: Path | None = None,
) -> ArtifactRecord:
    artifact, _ = save_artifact_with_path(artifact_type, label, data, source, case_path=case_path)
    return artifact


def display_path(path: str | Path) -> str:
    resolved = Path(path).resolve()
    try:
        return str(resolved.relative_to(PROJECT_DIR)).replace("\\", "/")
    except ValueError:
        return str(resolved)


def _latest_domain_artifact(target: str) -> ArtifactRecord | None:
    normalized = normalize_domain(target)
    if not normalized:
        return None
    candidates = []
    output_artifacts = OUTPUT_DIR / "artifacts.json"
    if output_artifacts.exists():
        try:
            candidates.extend(load_artifacts(OUTPUT_DIR))
        except Exception:
            pass
    for path in sorted(CASE_DIR.glob("*_domain_*.json"), reverse=True):
        try:
            candidates.append(
                ArtifactRecord.from_dict(
                    json.loads(path.read_text(encoding="utf-8"))
                )
            )
        except Exception:
            continue
    matching = []
    for artifact in candidates:
        if artifact.type != "domain":
            continue
        artifact_domain = normalize_domain(
            str((artifact.data or {}).get("domain") or artifact.label)
        )
        if artifact_domain == normalized:
            matching.append(artifact)
    if not matching:
        return None
    return max(
        matching,
        key=lambda artifact: (
            _domain_artifact_richness(artifact.data or {}),
            artifact.created_at,
        ),
    )


def _domain_artifact_richness(data: dict[str, Any]) -> int:
    score = len(data)
    for key in (
        "js_intelligence",
        "favicon_intelligence",
        "cloud_buckets",
        "oauth_intelligence",
        "historical_intelligence",
        "discovery",
        "traffic_chain",
    ):
        if data.get(key):
            score += 100
    score += min(len((data.get("devtools") or {}).get("network_requests") or []), 200)
    score += min(len(data.get("api_endpoints") or []), 200)
    return score


def _mention_report_artifacts(record: ArtifactRecord) -> list[ArtifactRecord]:
    domain = _latest_domain_artifact(record.label)
    return ([domain] if domain else []) + [record]


def _append_unique(rows: list[Any], value: str) -> None:
    if value not in rows:
        rows.append(value)


def _append_execution_stage(rows: list[dict[str, str]], stage: str, status: str) -> list[dict[str, str]]:
    output = [row for row in rows if row.get("stage") != stage]
    output.append({"stage": stage, "status": status})
    return output


def _workflow_execution_status(
    steps: list[dict[str, Any]],
    agent: str,
    success_detail: str,
) -> str:
    row = next((item for item in steps if item.get("agent") == agent), {})
    status = str(row.get("status") or "done").lower()
    if status == "failed":
        return f"failed: {row.get('reason') or 'module error'}"
    if status == "skipped":
        return f"skipped: {row.get('reason') or 'not applicable'}"
    return success_detail


def _recover_module(
    stage: str,
    operation: Any,
    fallback: Any,
    case_path: Path,
    execution_log: list[dict[str, str]],
) -> Any:
    try:
        return operation()
    except Exception as exc:
        reason = f"{type(exc).__name__}: {exc}"
        execution_log.append({"stage": stage, "status": f"failed: {reason}"})
        append_debug(case_path, f"[MODULE][{stage}] {reason}\n{traceback.format_exc()}")
        log_warn(f"{stage.replace('_', ' ').title()}: {t('status.failed')}")
        return fallback


def _partial_domain_result(domain_input: str, exc: Exception) -> dict[str, Any]:
    domain = normalize_domain(domain_input) or domain_input.strip()
    reason = f"{type(exc).__name__}: {exc}"
    return {
        "type": "domain_analysis",
        "input": domain_input,
        "host": domain,
        "domain": domain,
        "dns": {},
        "reverse_dns": [],
        "email_auth": {"spf": [], "dmarc": [], "dkim_hints": []},
        "rdap": {},
        "asn_bgp": [],
        "tls_certificate": {},
        "certificate_transparency": [],
        "subdomains": [],
        "http": {"status_code": None, "headers": {}},
        "http_surface": {
            "status_code": None,
            "headers": {},
            "probes": [],
            "redirect_chain": [],
            "interesting_paths": [],
            "security_signals": [],
            "errors": [reason],
        },
        "security_headers": {},
        "security_signals": [],
        "security_findings": [],
        "html": {},
        "devtools": {"available": False, "errors": [reason]},
        "traffic_chain": {},
        "javascript_intelligence": {},
        "js_intelligence": {},
        "favicon_intelligence": {},
        "cloud_buckets": {},
        "oauth_intelligence": {},
        "sensitive_public_files": {"findings": [], "errors": []},
        "historical_intelligence": {"status": "failed", "sources": [], "errors": [reason]},
        "reputation_intelligence": {"status": "failed", "errors": [reason]},
        "technologies": [],
        "detected_technologies": [],
        "api_endpoints": [],
        "emails": [],
        "phones": [],
        "social_links": [],
        "social_profiles": [],
        "linked_ip_addresses": [],
        "port_surface": {"status": "failed", "open_ports": [], "summary": {}, "errors": [reason]},
        "sources": [],
        "execution_log": [{"stage": "domain_analysis", "status": f"failed: {reason}"}],
        "analyst_timeline": [timeline_event("Domain analysis failed", detail="Continuing with partial report")],
        "errors": [reason],
        "timestamp": utc_now(),
    }


def _partial_ip_result(ip: str, exc: Exception) -> dict[str, Any]:
    parsed = ipaddress.ip_address(ip)
    reason = f"{type(exc).__name__}: {exc}"
    summary = {
        "ip": ip,
        "open_ports": 0,
        "detected_services": 0,
        "detected_technologies": 0,
        "risk_signals": 0,
    }
    return {
        "ip": ip,
        "version": parsed.version,
        "is_private": parsed.is_private,
        "country": "",
        "city": "",
        "asn": "",
        "organization": "",
        "provider": "",
        "reverse_dns": "",
        "hosting_or_datacenter": False,
        "vpn_proxy_tor": False,
        "rdap": {},
        "port_surface": {"status": "failed", "open_ports": [], "summary": {}, "errors": [reason]},
        "ip_intelligence": {
            "status": "failed",
            "summary": summary,
            "geo": {},
            "asn": {},
            "provider": {},
            "registry": {},
            "classification": {},
            "services": [],
            "ports": [],
            "technologies": [],
            "relationships": {},
            "blueprint": {},
            "timeline": [{"stage": "IP analysis", "status": "failed", "detail": reason}],
            "risk_signals": [],
            "evidence": [],
            "insights": [],
            "http_observations": [],
            "tls_observations": [],
        },
        "sources": [],
        "errors": [reason],
        "checked_at": utc_now(),
    }


def state_decoded_artifacts(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    output = []
    for row in rows:
        item_type = str(row.get("type") or "")
        notes = str(row.get("notes") or "")
        if item_type == "Endpoint":
            continue
        if item_type in {"Base64", "Base64URL"} and "binary payload" in notes:
            continue
        output.append(
            {
                "type": item_type,
                "value_masked": str(row.get("value_masked") or ""),
                "source": str(row.get("source") or ""),
            }
        )
        if len(output) >= 50:
            break
    return output


def state_sensitive_files(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "path": str(row.get("path") or ""),
            "url": str(row.get("url") or ""),
            "status": str(row.get("status") or ""),
        }
        for row in rows[:50]
    ]


def state_endpoints(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "endpoint": str(row.get("endpoint") or ""),
            "method": str(row.get("method") or ""),
            "risk": str(row.get("risk") or ""),
        }
        for row in rows[:50]
    ]


def state_strings(rows: list[Any]) -> list[str]:
    return [str(item) for item in rows[:50]]


def data_line(key: str, value: Any) -> None:
    console.print(f"[grey58]{escape(str(key))}[/grey58] [white]{escape(format_value(value))}[/white]")


def log_ok(message: str) -> None:
    console.print(f"[green][+][/green] {escape(message)}")


def log_warn(message: str) -> None:
    console.print(f"[yellow][!][/yellow] {escape(message)}")


def log_error(message: str) -> None:
    console.print(f"[red][-][/red] {escape(message)}")


def log_secondary(message: str) -> None:
    console.print(f"[grey58]{escape(message)}[/grey58]")


def print_traffic_live(row: dict[str, Any]) -> None:
    sequence = int(row.get("sequence") or row.get("id") or 0)
    resource = str(row.get("resource_type") or "other").upper()[:10].ljust(10)
    status = str(row.get("status") or row.get("failure_text") or "ERR")[:8].ljust(8)
    duration = f"{int(row.get('duration_ms') or row.get('duration') or 0)}ms".ljust(7)
    url = _traffic_display_url(str(row.get("url") or ""))
    tone = _traffic_tone(row)
    console.print(
        f"[grey58][{sequence:03d}][/grey58] "
        f"[{tone}]{escape(resource)}[/] "
        f"{escape(status)} {escape(duration)} {escape(url)}"
    )


def _traffic_display_url(url: str) -> str:
    if not url:
        return ""
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if parsed.hostname:
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            return path if len(path) < 96 else f"{path[:93]}..."
    except Exception:
        pass
    return url if len(url) < 96 else f"{url[:93]}..."


def _traffic_tone(row: dict[str, Any]) -> str:
    resource = str(row.get("resource_type") or "").lower()
    url = str(row.get("url") or "").lower()
    status = int(row.get("status") or 0)
    if row.get("failure_text") or status >= 500:
        return "red"
    if status >= 400:
        return "yellow"
    if resource in {"document", "xhr", "fetch", "websocket"} or any(key in url for key in ("/api/", "graphql", "auth", "session")):
        return "cyan"
    if resource in {"script", "stylesheet"}:
        return "green"
    return "grey70"


def load_saved_artifacts() -> list[ArtifactRecord]:
    artifacts = []
    for path in sorted(CASE_DIR.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            artifacts.append(ArtifactRecord.from_dict(payload))
        except Exception as exc:
            log_warn(f"skipped artifact {path.name}: {exc}")
    return artifacts


if __name__ == "__main__":
    main()
