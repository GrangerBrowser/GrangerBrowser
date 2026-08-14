from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..i18n import DEFAULT_LANGUAGE, load_all_locales, load_locale, normalize_language


def export_mention_search_report(
    data: dict[str, Any],
    output_path: str | Path,
    language: str = DEFAULT_LANGUAGE,
) -> dict[str, Any]:
    lang = normalize_language(language)
    report_path = Path(output_path).expanduser().resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_dir = Path(__file__).resolve().parent
    env = Environment(
        loader=FileSystemLoader(str(report_dir / "templates")),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("mention_search.html")
    report = _build_report_data(data)
    html = template.render(
        language=lang,
        locale=load_locale(lang),
        report=report,
        report_css=(report_dir / "static" / "mention_search.css").read_text(encoding="utf-8"),
        report_js=env.from_string(
            (report_dir / "static" / "mention_search.js").read_text(encoding="utf-8")
        ).render(report=report, language=lang, locales=load_all_locales()),
    )
    report_path.write_text(html, encoding="utf-8")
    return {"report": report_path, "report_data": report}


def _build_report_data(data: dict[str, Any]) -> dict[str, Any]:
    summary = data.get("summary") or {}
    matches = [_match_row(row) for row in (data.get("matches") or [])]
    pages = data.get("pages") or []
    return {
        "title": "Mention Search",
        "target": str(data.get("target") or ""),
        "primary_url": str(data.get("primary_url") or ""),
        "keywords": [str(value) for value in data.get("keywords") or []],
        "search_modes": data.get("search_modes") or [],
        "timestamp": str(data.get("timestamp") or ""),
        "summary": summary,
        "pages": pages,
        "matches": matches,
        "errors": data.get("errors") or [],
        "limits": data.get("limits") or {},
    }


def _match_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "keyword": str(row.get("keyword") or ""),
        "matched_text": str(row.get("matched_text") or ""),
        "source_type": str(row.get("source_type") or ""),
        "page_url": str(row.get("page_url") or row.get("source_url") or ""),
        "page_path": str(row.get("page_path") or ""),
        "navigation_url": str(row.get("navigation_url") or row.get("page_url") or ""),
        "target_url": str(row.get("target_url") or ""),
        "element_type": str(row.get("element_type") or ""),
        "section": str(row.get("section") or ""),
        "location": str(row.get("location") or ""),
        "html_path": str(row.get("html_path") or ""),
        "css_selector": str(row.get("css_selector") or ""),
        "xpath": str(row.get("xpath") or ""),
        "method": str(row.get("method") or ""),
        "line": row.get("line") or 0,
        "context_before": str(row.get("context_before") or ""),
        "context_after": str(row.get("context_after") or ""),
        "count": row.get("count") or 1,
        "confidence": str(row.get("confidence") or ""),
    }
