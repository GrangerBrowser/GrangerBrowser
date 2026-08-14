from __future__ import annotations

from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from difflib import SequenceMatcher
import hashlib
import json
import re
from typing import Any, Callable, Iterable
from urllib.parse import quote, urljoin, urlparse, urlunparse

import requests
import urllib3

from .models import utc_now


DebugLog = Callable[[str], None]

TIMEOUT = 8
MAX_PAGES = 100
MAX_DEPTH = 3
MAX_BROWSER_PAGES = 20
MAX_JS_FILES = 40
MAX_CSS_FILES = 20
MAX_SOURCE_MAPS = 10
MAX_NETWORK_RESPONSES = 100
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_MATCHES = 8000
MAX_MATCHES_PER_DOCUMENT = 100
USER_AGENT = "Pamp/Mention-Search"
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
SPECIAL_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/manifest.json",
)
SENSITIVE_MARKERS = (
    "token",
    "secret",
    "key",
    "password",
    "auth",
    "session",
    "jwt",
    "bearer",
    "client_secret",
    "access_token",
    "refresh_token",
    "callback",
    "admin",
    "internal",
    "debug",
    "private",
)
INTERESTING_SOURCES = {
    "url",
    "js",
    "json",
    "sitemap",
    "robots",
    "wayback",
    "api",
    "oauth",
    "cloud",
}
WORD_PATTERN = re.compile(r"[@\w.-]{2,}", re.UNICODE)
_DOM_CAPTURE_SCRIPT = r"""() => {
  const selectorFor = (node) => {
    if (!node || node.nodeType !== 1) return "";
    if (node.id) return `#${CSS.escape(node.id)}`;
    const parts = [];
    let current = node;
    while (current && current.nodeType === 1 && parts.length < 7) {
      let part = current.tagName.toLowerCase();
      const classes = Array.from(current.classList || []).filter(Boolean).slice(0, 2);
      if (classes.length) part += "." + classes.map(value => CSS.escape(value)).join(".");
      const siblings = current.parentElement
        ? Array.from(current.parentElement.children).filter(item => item.tagName === current.tagName)
        : [];
      if (siblings.length > 1) part += `:nth-of-type(${siblings.indexOf(current) + 1})`;
      parts.unshift(part);
      current = current.parentElement;
      if (current?.tagName?.toLowerCase() === "html") break;
    }
    return parts.join(" > ");
  };
  const xpathFor = (node) => {
    if (!node || node.nodeType !== 1) return "";
    const parts = [];
    let current = node;
    while (current && current.nodeType === 1) {
      const tag = current.tagName.toLowerCase();
      const siblings = current.parentElement
        ? Array.from(current.parentElement.children).filter(item => item.tagName === current.tagName)
        : [];
      parts.unshift(`${tag}[${Math.max(1, siblings.indexOf(current) + 1)}]`);
      current = current.parentElement;
    }
    return "/" + parts.join("/");
  };
  const sectionFor = (node) => {
    const parent = node.closest("nav,header,footer,aside,form,table,[role=menu],[role=navigation],[aria-label]");
    if (!parent) return "Page";
    const tag = parent.tagName.toLowerCase();
    if (tag === "nav" || parent.matches("[role=menu],[role=navigation]")) return "Navigation";
    if (tag === "header") return "Header";
    if (tag === "footer") return "Footer";
    if (tag === "aside") return "Sidebar";
    if (tag === "form") return "Form";
    if (tag === "table") return "Table";
    return parent.getAttribute("aria-label") || "Section";
  };
  const typeFor = (node) => {
    const tag = node.tagName.toLowerCase();
    const context = `${node.id || ""} ${node.className || ""}`.toLowerCase();
    if (node.closest("nav,[role=menu],[role=navigation]")) return "Navigation";
    if (tag === "button" || node.getAttribute("role") === "button") return "Button";
    if (tag === "a") return "Link";
    if (tag === "form") return "Form";
    if (["input", "textarea", "select", "option"].includes(tag)) return "Form Field";
    if (tag === "label") return "Label";
    if (["th", "td", "table"].includes(tag)) return "Table";
    if (tag === "li") return "List Item";
    if (tag === "img") return "Image";
    if (tag === "title" && node.closest("svg")) return "SVG Title";
    if (tag === "canvas") return "Canvas Fallback";
    if (context.includes("breadcrumb")) return "Breadcrumb";
    if (context.includes("product") || context.includes("card")) return "Product Card";
    if (/^h[1-6]$/.test(tag)) return "Heading";
    if (tag === "p") return "Paragraph";
    return "Element";
  };
  const nodes = Array.from(document.querySelectorAll(
    "button,a,label,input,textarea,select,option,img,form,li,p,h1,h2,h3,h4,h5,h6,th,td,summary,[role=button],[role=menuitem],[aria-label],[title],svg title,canvas"
  )).slice(0, 4000);
  const elements = nodes.map(node => {
    const values = [
      node.innerText,
      node.getAttribute("aria-label"),
      node.getAttribute("placeholder"),
      node.getAttribute("title"),
      node.getAttribute("alt"),
      node.getAttribute("value")
    ].filter(Boolean).map(value => String(value).trim()).filter(Boolean);
    return {
      text: [...new Set(values)].join(" | ").slice(0, 4000),
      type: typeFor(node),
      location: `${typeFor(node)} ${node.tagName.toLowerCase()}`,
      selector: selectorFor(node),
      xpath: xpathFor(node),
      section: sectionFor(node),
      targetUrl: node.href || node.action || ""
    };
  }).filter(row => row.text);
  return {
    elements,
    links: Array.from(document.querySelectorAll("[href]")).map(node => node.href).filter(Boolean),
    scripts: Array.from(document.scripts).map(node => node.src).filter(Boolean),
    styles: Array.from(document.querySelectorAll('link[rel="stylesheet"]')).map(node => node.href).filter(Boolean),
    metas: Array.from(document.querySelectorAll("meta")).map(node => `${node.name || node.property || ""}: ${node.content || ""}`)
  };
}"""


@dataclass(frozen=True)
class SourceDocument:
    source_type: str
    source_url: str
    location: str
    text: str
    element_type: str = ""
    selector: str = ""
    xpath: str = ""
    page_url: str = ""
    section: str = ""
    method: str = ""
    target_url: str = ""


def search_mentions(
    target_input: str,
    keyword_input: str,
    mode: str = "default",
    existing_domain_data: dict[str, Any] | None = None,
    debug_log: DebugLog | None = None,
) -> dict[str, Any]:
    target = normalize_target(target_input)
    if not target["host"]:
        raise ValueError("Target domain or URL is empty")
    keywords = parse_keywords(keyword_input)
    if not keywords:
        raise ValueError("Keyword or keywords are empty")
    invalid_keywords = [keyword for keyword in keywords if not is_meaningful_query(keyword)]
    if invalid_keywords:
        raise ValueError(
            "Search query is too short or contains too little meaningful text: "
            + ", ".join(invalid_keywords)
        )
    modes = normalize_modes(mode)
    variants_by_keyword = {
        keyword: generate_variants(keyword)
        for keyword in keywords
    }
    errors: list[str] = []
    documents: list[SourceDocument] = []
    artifact_docs: list[SourceDocument] = []
    coverage: Counter[str] = Counter()

    if existing_domain_data:
        artifact_docs = _documents_from_domain_artifact(existing_domain_data)
        coverage.update(row.source_type for row in artifact_docs)

    live = _safe_collection(
        "HTTP",
        lambda: _collect_http_sources(target, debug_log, errors),
        _empty_live_collection(target["url"]),
        debug_log,
        errors,
    )
    documents.extend(live["documents"])
    coverage.update(live["coverage"])
    primary_url = live.get("primary_url") or target["url"]

    browser = _safe_collection(
        "BROWSER",
        lambda: _collect_browser_sources(
            primary_url,
            target["host"],
            live.get("browser_urls") or [],
            debug_log,
            errors,
        ),
        {"documents": [], "coverage": Counter(), "js_urls": [], "css_urls": [], "page_urls": [], "stats": {}},
        debug_log,
        errors,
    )
    documents.extend(browser["documents"])
    coverage.update(browser["coverage"])

    asset_urls = _unique_strings(
        live["js_urls"] + browser["js_urls"],
        MAX_JS_FILES,
    )
    css_urls = _unique_strings(
        live["css_urls"] + browser["css_urls"],
        MAX_CSS_FILES,
    )
    asset_docs = _safe_collection(
        "ASSETS",
        lambda: _collect_assets(
            asset_urls,
            css_urls,
            target["host"],
            debug_log,
            errors,
        ),
        [],
        debug_log,
        errors,
    )
    documents.extend(asset_docs)
    coverage.update(row.source_type for row in asset_docs)
    documents.extend(artifact_docs)

    matches = _find_matches(
        documents,
        keywords,
        variants_by_keyword,
        modes,
    )
    scan_stats = Counter(live.get("stats") or {})
    scan_stats.update(browser.get("stats") or {})
    scan_stats["js_files_scanned"] = sum(1 for row in asset_docs if row.source_type == "js")
    scan_stats["css_files_scanned"] = sum(1 for row in asset_docs if row.source_type == "css")
    scan_stats["source_maps_scanned"] = sum(1 for row in asset_docs if row.source_type == "sourcemap")
    scan_stats["service_workers_scanned"] = sum(
        1 for row in asset_docs if row.source_type == "service_worker"
    )
    page_urls = _unique_strings(
        (live.get("page_urls") or []) + (browser.get("page_urls") or []),
        MAX_PAGES,
    )
    summary = _build_summary(matches, coverage, scan_stats, page_urls)
    ranked_matches = sorted(
        matches,
        key=lambda row: (
            {"sensitive": 3, "interesting": 2, "info": 1}.get(row["risk"], 0),
            {"high": 3, "medium": 2, "low": 1}.get(row["confidence"], 0),
            row.get("count", 1),
        ),
        reverse=True,
    )
    top_matches = []
    top_keys = set()
    for row in ranked_matches:
        key = (
            row.get("keyword"),
            row.get("risk"),
            row.get("source_type"),
            row.get("source_url"),
            row.get("location"),
        )
        if key in top_keys:
            continue
        top_keys.add(key)
        top_matches.append(row)
        if len(top_matches) >= 20:
            break
    return {
        "type": "mention_search",
        "target": target["host"],
        "target_input": target_input,
        "primary_url": primary_url,
        "keywords": keywords,
        "search_modes": modes,
        "variants": [
            {"keyword": keyword, "values": variants_by_keyword[keyword]}
            for keyword in keywords
        ],
        "limits": {
            "max_pages": MAX_PAGES,
            "max_js_files": MAX_JS_FILES,
            "max_network_responses": MAX_NETWORK_RESPONSES,
            "max_response_size": MAX_RESPONSE_BYTES,
            "timeout": TIMEOUT,
            "max_depth": MAX_DEPTH,
            "same_domain_only": True,
        },
        "summary": summary,
        "pages": _page_results(matches, page_urls),
        "matches": matches,
        "top_matches": top_matches,
        "source_coverage": dict(sorted(coverage.items())),
        "errors": errors,
        "timestamp": utc_now(),
    }


def hunt_mentions(
    target_input: str,
    keyword_input: str,
    mode: str = "default",
    existing_domain_data: dict[str, Any] | None = None,
    debug_log: DebugLog | None = None,
) -> dict[str, Any]:
    """Backward-compatible alias for older integrations."""
    return search_mentions(
        target_input,
        keyword_input,
        mode=mode,
        existing_domain_data=existing_domain_data,
        debug_log=debug_log,
    )


def normalize_target(value: str) -> dict[str, str]:
    raw = str(value or "").strip()
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    host = (parsed.hostname or "").strip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except Exception:
        pass
    scheme = parsed.scheme if parsed.scheme in {"http", "https"} else "https"
    return {
        "input": raw,
        "host": host,
        "url": urlunparse((scheme, parsed.netloc or host, parsed.path or "/", "", parsed.query, "")),
    }


def parse_keywords(value: str) -> list[str]:
    rows = []
    seen = set()
    for item in re.split(r"[,\r\n]+", str(value or "")):
        keyword = item.strip()
        key = keyword.casefold()
        if keyword and key not in seen:
            seen.add(key)
            rows.append(keyword[:180])
    return rows[:40]


def is_meaningful_query(value: str) -> bool:
    normalized = re.sub(r"\s+", " ", str(value or "")).strip()
    alphanumeric = [character for character in normalized if character.isalnum()]
    return len(normalized) >= 2 and len(alphanumeric) >= 2


def normalize_modes(value: str) -> list[str]:
    raw = str(value or "default").strip().lower()
    mapping = {
        "1": ["exact"],
        "exact": ["exact"],
        "2": ["case-insensitive"],
        "case": ["case-insensitive"],
        "case-insensitive": ["case-insensitive"],
        "3": ["fuzzy"],
        "fuzzy": ["fuzzy"],
        "4": ["variants"],
        "variants": ["variants"],
        "all": ["exact", "case-insensitive", "fuzzy", "variants"],
        "default": ["case-insensitive", "variants"],
        "": ["case-insensitive", "variants"],
    }
    if raw in mapping:
        return mapping[raw]
    modes = []
    for item in re.split(r"[,+\s]+", raw):
        normalized = mapping.get(item, [])
        for mode in normalized:
            if mode not in modes:
                modes.append(mode)
    return modes or ["case-insensitive", "variants"]


def generate_variants(keyword: str) -> list[str]:
    raw = str(keyword or "").strip()
    if not raw:
        return []
    values = [
        raw,
        raw.lower(),
        raw.upper(),
        raw.capitalize(),
    ]
    core = raw.lstrip("@")
    simple = bool(re.fullmatch(r"[\w.-]+", core, re.UNICODE))
    if simple and core:
        values.extend(
            [
                f"@{core}",
                f"{core}_",
                f"{core}-",
                f"{core}.",
                f"{core}/",
                f"{core}:",
                f"{core}@",
                f"{core}s",
            ]
        )
        for suffix in ("Login", "Auth", "Token", "Callback"):
            values.append(f"{core}{suffix}")
        for suffix in ("login", "auth", "token", "callback"):
            values.append(f"{core}_{suffix}")
            values.append(f"{core}-{suffix}")
    return _unique_strings(values, 40, case_sensitive=True)


def _collect_http_sources(
    target: dict[str, str],
    debug_log: DebugLog | None,
    errors: list[str],
) -> dict[str, Any]:
    documents: list[SourceDocument] = []
    coverage: Counter[str] = Counter()
    stats: Counter[str] = Counter()
    js_urls: list[str] = []
    css_urls: list[str] = []
    page_urls: list[str] = []
    browser_urls: list[str] = []
    primary_url = ""
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    candidates = [target["url"]]
    for scheme in ("https", "http"):
        candidate = f"{scheme}://{target['host']}/"
        if candidate not in candidates:
            candidates.append(candidate)
    main_response = None
    main_body = b""
    for url in candidates:
        try:
            response = session.get(
                url,
                timeout=TIMEOUT,
                allow_redirects=True,
                verify=False,
                stream=True,
            )
            body = _read_response(response)
            if response.status_code < 500 and body:
                main_response = response
                main_body = body
                primary_url = response.url
                _add_response_documents(documents, response, body, "html")
                break
        except Exception as exc:
            _record_error(errors, debug_log, "[MENTION][FETCH]", f"url={url} error={exc}")
    if main_response is None:
        return {
            "documents": documents,
            "coverage": coverage,
            "js_urls": js_urls,
            "css_urls": css_urls,
            "primary_url": target["url"],
            "page_urls": page_urls,
            "browser_urls": browser_urls,
            "stats": dict(stats),
        }

    page_urls.append(main_response.url)
    stats["pages_scanned"] += 1
    coverage.update(row.source_type for row in documents)
    initial_html = _decode_body(main_response, main_body)
    parsed = _parse_html_sources(initial_html, main_response.url)
    documents.extend(parsed["documents"])
    js_urls.extend(parsed["js_urls"])
    css_urls.extend(parsed["css_urls"])
    stats.update(parsed.get("stats") or {})
    if parsed.get("needs_browser"):
        browser_urls.append(main_response.url)
    coverage.update(row.source_type for row in parsed["documents"])

    queue = deque(
        (url, 1)
        for url in parsed["links"]
        if _same_host(url, target["host"])
    )
    visited = {_canonical_url_key(main_response.url)}
    page_count = 1
    while queue and page_count < MAX_PAGES:
        batch = []
        while queue and len(batch) < 8 and page_count + len(batch) < MAX_PAGES:
            url, depth = queue.popleft()
            key = _canonical_url_key(url)
            if not key or key in visited or depth > MAX_DEPTH or _is_asset_url(url):
                continue
            visited.add(key)
            batch.append((url, depth))
        if not batch:
            continue
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {
                executor.submit(_fetch_page, session, url): (url, depth)
                for url, depth in batch
            }
            for future in as_completed(futures):
                url, depth = futures[future]
                try:
                    fetched = future.result()
                except Exception as exc:
                    _record_error(errors, debug_log, "[MENTION][FETCH]", f"url={url} error={exc}")
                    continue
                if not fetched:
                    continue
                response, body = fetched
                page_count += 1
                page_urls.append(response.url)
                stats["pages_scanned"] += 1
                _add_response_documents(documents, response, body, "html")
                html = _decode_body(response, body)
                page = _parse_html_sources(html, response.url)
                documents.extend(page["documents"])
                js_urls.extend(page["js_urls"])
                css_urls.extend(page["css_urls"])
                stats.update(page.get("stats") or {})
                if page.get("needs_browser"):
                    browser_urls.append(response.url)
                coverage.update(row.source_type for row in page["documents"])
                if depth < MAX_DEPTH:
                    queue.extend(
                        (link, depth + 1)
                        for link in page["links"]
                        if _same_host(link, target["host"])
                    )

    for path in SPECIAL_PATHS:
        url = urljoin(primary_url, path)
        try:
            response = session.get(
                url,
                timeout=TIMEOUT,
                allow_redirects=True,
                verify=False,
                stream=True,
            )
            if response.status_code >= 400:
                continue
            body = _read_response(response)
            if not body:
                continue
            source_type = (
                "robots" if path.endswith("robots.txt")
                else "sitemap" if path.endswith("sitemap.xml")
                else "json" if path.endswith(".json")
                else "html"
            )
            documents.append(
                SourceDocument(
                    source_type,
                    response.url,
                    path.lstrip("/"),
                    _decode_body(response, body),
                )
            )
            coverage[source_type] += 1
        except Exception as exc:
            _record_error(errors, debug_log, "[MENTION][FETCH]", f"url={url} error={exc}")

    unique_page_urls = _unique_strings(page_urls, MAX_PAGES)
    stats["pages_scanned"] = len(unique_page_urls)
    return {
        "documents": documents,
        "coverage": coverage,
        "js_urls": js_urls,
        "css_urls": css_urls,
        "primary_url": primary_url,
        "page_urls": unique_page_urls,
        "browser_urls": _unique_strings(browser_urls, MAX_BROWSER_PAGES),
        "stats": dict(stats),
    }


def _collect_browser_sources(
    url: str,
    host: str,
    candidate_urls: list[str],
    debug_log: DebugLog | None,
    errors: list[str],
) -> dict[str, Any]:
    documents: list[SourceDocument] = []
    coverage: Counter[str] = Counter()
    stats: Counter[str] = Counter()
    js_urls: list[str] = []
    css_urls: list[str] = []
    page_urls: list[str] = []
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        _record_error(errors, debug_log, "[MENTION][PLAYWRIGHT]", f"target={url} error={exc}")
        return {
            "documents": [],
            "coverage": coverage,
            "js_urls": [],
            "css_urls": [],
            "page_urls": [],
            "stats": {},
        }

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent=USER_AGENT,
                viewport={"width": 1366, "height": 768},
            )
            page = context.new_page()
            responses: list[Any] = []
            page.on("response", lambda response: responses.append(response))
            targets = _unique_strings([url] + list(candidate_urls), MAX_BROWSER_PAGES)
            seen_network = set()
            for target_url in targets:
                responses.clear()
                try:
                    page.goto(target_url, wait_until="domcontentloaded", timeout=TIMEOUT * 1000)
                    try:
                        page.wait_for_load_state("networkidle", timeout=3_000)
                    except PlaywrightTimeoutError:
                        pass
                except Exception as exc:
                    _record_error(
                        errors,
                        debug_log,
                        "[MENTION][PLAYWRIGHT]",
                        f"target={target_url} error={exc}",
                    )
                    continue

                current_url = page.url
                page_urls.append(current_url)
                stats["browser_pages"] += 1
                try:
                    dom = page.evaluate(_DOM_CAPTURE_SCRIPT)
                    elements = dom.get("elements") or []
                    stats["dom_elements_scanned"] += len(elements)
                    for element in elements:
                        value = str(element.get("text") or "").strip()
                        if not value:
                            continue
                        element_type = str(element.get("type") or "Element")
                        stats[_stat_key_for_element(element_type)] += 1
                        documents.append(
                            SourceDocument(
                                "dom",
                                current_url,
                                str(element.get("location") or element_type),
                                value[:MAX_RESPONSE_BYTES],
                                element_type=element_type,
                                selector=str(element.get("selector") or ""),
                                xpath=str(element.get("xpath") or ""),
                                page_url=current_url,
                                section=str(element.get("section") or ""),
                                target_url=str(element.get("targetUrl") or ""),
                            )
                        )
                    for value in dom.get("links") or []:
                        cleaned = _clean_source_url(value)
                        if cleaned:
                            documents.append(
                                SourceDocument(
                                    "url",
                                    current_url,
                                    "link URL",
                                    cleaned,
                                    element_type="Link",
                                    page_url=current_url,
                                    target_url=cleaned,
                                )
                            )
                    for value in dom.get("metas") or []:
                        documents.append(
                            SourceDocument(
                                "meta",
                                current_url,
                                "rendered meta",
                                value,
                                element_type="Meta",
                                page_url=current_url,
                            )
                        )
                    js_urls.extend(dom.get("scripts") or [])
                    css_urls.extend(dom.get("styles") or [])
                except Exception as exc:
                    _record_error(
                        errors,
                        debug_log,
                        "[MENTION][PLAYWRIGHT]",
                        f"target={current_url} error={exc}",
                    )

                for cookie in context.cookies():
                    name = str(cookie.get("name") or "")
                    if name:
                        documents.append(
                            SourceDocument(
                                "cookie",
                                current_url,
                                "cookie:name",
                                name,
                                element_type="Cookie",
                                page_url=current_url,
                            )
                        )
                        stats["cookies_scanned"] += 1
                try:
                    storage = page.evaluate(
                        """() => ({
                          local: Object.entries(localStorage),
                          session: Object.entries(sessionStorage)
                        })"""
                    )
                    for kind in ("local", "session"):
                        for key, value in storage.get(kind) or []:
                            documents.append(
                                SourceDocument(
                                    "storage",
                                    current_url,
                                    f"{kind}Storage:key",
                                    f"{key} {value}",
                                    element_type=f"{kind}Storage",
                                    page_url=current_url,
                                )
                            )
                            stats["storage_items_scanned"] += 1
                except Exception:
                    pass

                for response in responses[:MAX_NETWORK_RESPONSES]:
                    network_url = _clean_source_url(str(response.url or ""))
                    if not network_url or network_url in seen_network:
                        continue
                    seen_network.add(network_url)
                    stats["network_requests_scanned"] += 1
                    request = response.request
                    method = str(request.method or "")
                    documents.append(
                        SourceDocument(
                            "url",
                            network_url,
                            "network:url",
                            network_url,
                            element_type="Network Request",
                            page_url=current_url,
                            method=method,
                            target_url=network_url,
                        )
                    )
                    header_text = "\n".join(
                        f"{key}: {value}"
                        for key, value in (response.headers or {}).items()
                    )
                    if header_text:
                        documents.append(
                            SourceDocument(
                                "header",
                                network_url,
                                "network:headers",
                                header_text,
                                element_type="Headers",
                                page_url=current_url,
                                method=method,
                            )
                        )
                    resource_type = str(request.resource_type or "").lower()
                    if resource_type == "script":
                        js_urls.append(network_url)
                    elif resource_type == "stylesheet":
                        css_urls.append(network_url)
                    content_type = str((response.headers or {}).get("content-type") or "").lower()
                    if (
                        _same_host(network_url, host)
                        and ("json" in content_type or resource_type in {"xhr", "fetch"})
                    ):
                        stats["api_requests_scanned"] += 1
                        try:
                            body = response.body()
                            if 0 < len(body) <= MAX_RESPONSE_BYTES:
                                documents.append(
                                    SourceDocument(
                                        "api",
                                        network_url,
                                        "network:response",
                                        body.decode("utf-8", errors="replace"),
                                        element_type="API Response",
                                        page_url=current_url,
                                        method=method,
                                        target_url=network_url,
                                    )
                                )
                        except Exception as exc:
                            _record_error(
                                errors,
                                debug_log,
                                "[MENTION][FETCH]",
                                f"url={network_url} error={exc}",
                            )
            browser.close()
    except Exception as exc:
        _record_error(errors, debug_log, "[MENTION][PLAYWRIGHT]", f"target={url} error={exc}")
    coverage.update(row.source_type for row in documents)
    return {
        "documents": documents,
        "coverage": coverage,
        "js_urls": js_urls,
        "css_urls": css_urls,
        "page_urls": _unique_strings(page_urls, MAX_BROWSER_PAGES),
        "stats": dict(stats),
    }


def _collect_assets(
    js_urls: list[str],
    css_urls: list[str],
    host: str,
    debug_log: DebugLog | None,
    errors: list[str],
) -> list[SourceDocument]:
    tasks = [
        (url, "js")
        for url in js_urls[:MAX_JS_FILES]
        if _same_host(url, host)
    ]
    tasks.extend(
        (url, "css")
        for url in css_urls[:MAX_CSS_FILES]
        if _same_host(url, host)
    )
    documents = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {
            executor.submit(_fetch_asset, url, source_type): (url, source_type)
            for url, source_type in tasks
        }
        for future in as_completed(futures):
            url, source_type = futures[future]
            try:
                row = future.result()
                if row:
                    documents.append(row)
            except Exception as exc:
                _record_error(errors, debug_log, "[MENTION][JS]", f"url={url} error={exc}")
    source_maps = []
    service_workers = []
    for document in documents:
        if document.source_type != "js":
            continue
        for value in re.findall(r"sourceMappingURL\s*=\s*([^\s*]+)", document.text, re.I):
            map_url = _clean_source_url(urljoin(document.source_url, value.strip("\"'")))
            if map_url and _same_host(map_url, host):
                source_maps.append(map_url)
        for value in re.findall(
            r"serviceWorker\s*\.\s*register\s*\(\s*[\"']([^\"']+)",
            document.text,
            re.I,
        ):
            worker_url = _clean_source_url(urljoin(document.source_url, value))
            if worker_url and _same_host(worker_url, host):
                service_workers.append(worker_url)
    for map_url in _unique_strings(source_maps, MAX_SOURCE_MAPS):
        try:
            row = _fetch_asset(map_url, "sourcemap")
            if row:
                documents.append(row)
        except Exception as exc:
            _record_error(errors, debug_log, "[MENTION][JS]", f"url={map_url} error={exc}")
    for worker_url in _unique_strings(service_workers, 5):
        try:
            row = _fetch_asset(worker_url, "service_worker")
            if row:
                documents.append(row)
        except Exception as exc:
            _record_error(errors, debug_log, "[MENTION][JS]", f"url={worker_url} error={exc}")
    return documents


def _documents_from_domain_artifact(data: dict[str, Any]) -> list[SourceDocument]:
    documents: list[SourceDocument] = []
    domain = str(data.get("domain") or data.get("host") or "")
    base_url = str((data.get("http_surface") or {}).get("primary_url") or f"https://{domain}/")
    html = data.get("html") or {}
    for key in (
        "title",
        "meta_description",
        "meta_keywords",
        "canonical",
        "robots_meta",
        "favicon_url",
    ):
        _append_value_document(documents, "meta", base_url, key, html.get(key))
    for key, source_type in (
        ("html_comments", "comment"),
        ("meta_tags", "meta"),
        ("inline_scripts", "js"),
        ("external_links", "url"),
        ("script_links", "url"),
        ("external_css", "url"),
    ):
        _append_value_document(documents, source_type, base_url, key, html.get(key))

    surface = data.get("http_surface") or {}
    _append_value_document(documents, "header", base_url, "response headers", surface.get("headers"))
    _append_value_document(documents, "cookie", base_url, "cookie names", surface.get("cookie_names"))
    _append_value_document(documents, "robots", base_url, "interesting paths", surface.get("interesting_paths"))

    devtools = data.get("devtools") or {}
    for row in devtools.get("network_requests") or []:
        url = str(row.get("url") or "")
        _append_value_document(documents, "url", url, "network:url", url)
        _append_value_document(documents, "header", url, "network:headers", row.get("response_headers"))
    _append_value_document(documents, "cookie", base_url, "devtools cookies", devtools.get("cookies_names"))
    _append_value_document(documents, "storage", base_url, "localStorage", devtools.get("localStorage"))
    _append_value_document(documents, "storage", base_url, "sessionStorage", devtools.get("sessionStorage"))
    _append_value_document(documents, "dom", base_url, "dom links", devtools.get("dom_links"))
    _append_value_document(documents, "meta", base_url, "devtools meta", devtools.get("meta_tags"))

    for row in (data.get("js_intelligence") or {}).get("files") or []:
        source_url = _clean_source_url(str(row.get("value") or ""))
        if source_url:
            _append_value_document(documents, "js", source_url, "js file", row)
    for row in (data.get("js_intelligence") or {}).get("api_endpoints") or []:
        source_url = _clean_source_url(str(row.get("value") or "")).rstrip("$")
        if source_url:
            _append_value_document(documents, "api", source_url, "api endpoint", row)
    for row in data.get("api_endpoints") or []:
        source_url = _clean_source_url(str(row.get("endpoint") or "")).rstrip("$")
        if source_url:
            _append_value_document(documents, "api", source_url, "api endpoint", row)

    oauth = data.get("oauth_intelligence") or {}
    for key in ("providers", "auth_routes", "callback_urls", "client_ids", "scopes", "oidc_metadata", "session_indicators"):
        _append_value_document(documents, "oauth", base_url, key, oauth.get(key))
    cloud = data.get("cloud_buckets") or {}
    for key in ("candidates", "verified", "public_objects"):
        _append_value_document(documents, "cloud", base_url, key, cloud.get(key))

    historical = data.get("historical_intelligence") or {}
    wayback = historical.get("wayback") or {}
    _append_value_document(documents, "wayback", base_url, "wayback URLs", wayback.get("historical_urls"))
    _append_value_document(documents, "wayback", base_url, "wayback interesting URLs", wayback.get("interesting_urls"))
    discovery = data.get("discovery") or {}
    _append_value_document(documents, "url", base_url, "discovered paths", discovery.get("findings"))
    _append_value_document(documents, "url", base_url, "discovered results", discovery.get("all_results"))
    for key in ("social_links", "emails", "phones", "telegram_links"):
        _append_value_document(documents, "url", base_url, key, data.get(key))
    return documents


def _find_matches(
    documents: list[SourceDocument],
    keywords: list[str],
    variants_by_keyword: dict[str, list[str]],
    modes: list[str],
) -> list[dict[str, Any]]:
    rows: dict[tuple[str, ...], dict[str, Any]] = {}
    source_row_counts: Counter[str] = Counter()
    for document in documents:
        source_quota = _source_match_quota(document.source_type)
        if source_row_counts[document.source_type] >= source_quota:
            continue
        text = str(document.text or "")[:MAX_RESPONSE_BYTES]
        if not text:
            continue
        document_matches = 0
        for keyword in keywords:
            found = _matches_in_text(
                text,
                keyword,
                variants_by_keyword[keyword],
                modes,
            )
            for match in found:
                start, end = match["start"], match["end"]
                before = _compact_context(text[max(0, start - 80) : start])
                matched_text = _compact_context(text[start:end], 180)
                after = _compact_context(text[end : end + 80])
                surrounding = f"{before} {matched_text} {after}".lower()
                risk, notes = _match_risk(document, surrounding)
                line = text.count("\n", 0, start) + 1
                context_hash = hashlib.sha256(
                    f"{before}|{matched_text}|{after}".encode("utf-8", errors="ignore")
                ).hexdigest()[:16]
                page_url = document.page_url or document.source_url
                navigation_url = _navigation_url(document, matched_text)
                row = {
                    "keyword": keyword,
                    "matched_text": matched_text,
                    "variant": match["variant"],
                    "source_type": document.source_type,
                    "source_url": document.source_url,
                    "page_url": page_url,
                    "page_path": _display_page_path(page_url),
                    "navigation_url": navigation_url,
                    "target_url": document.target_url,
                    "location": document.location,
                    "element_type": document.element_type or _default_element_type(document.source_type),
                    "section": document.section,
                    "html_path": document.selector or document.xpath,
                    "css_selector": document.selector,
                    "xpath": document.xpath,
                    "method": document.method,
                    "line": line,
                    "context_before": before,
                    "context_after": after,
                    "context": f"{before}{matched_text}{after}",
                    "context_hash": context_hash,
                    "confidence": match["confidence"],
                    "risk": risk,
                    "notes": notes,
                    "count": 1,
                }
                key = (
                    keyword.casefold(),
                    matched_text.casefold(),
                    _canonical_url_key(document.source_url),
                    document.source_type,
                    document.location,
                    context_hash,
                )
                if key in rows:
                    rows[key]["count"] += 1
                else:
                    rows[key] = row
                    source_row_counts[document.source_type] += 1
                    document_matches += 1
                if len(rows) >= MAX_MATCHES:
                    break
                if source_row_counts[document.source_type] >= source_quota:
                    break
                if document_matches >= MAX_MATCHES_PER_DOCUMENT:
                    break
            if len(rows) >= MAX_MATCHES:
                break
            if source_row_counts[document.source_type] >= source_quota:
                break
            if document_matches >= MAX_MATCHES_PER_DOCUMENT:
                break
        if len(rows) >= MAX_MATCHES:
            break
    risk_rank = {"sensitive": 3, "interesting": 2, "info": 1}
    confidence_rank = {"high": 3, "medium": 2, "low": 1}
    return sorted(
        rows.values(),
        key=lambda row: (
            -risk_rank.get(row["risk"], 0),
            -confidence_rank.get(row["confidence"], 0),
            row["source_type"],
            row["source_url"],
            row["line"],
        ),
    )


def _source_match_quota(source_type: str) -> int:
    if source_type in {"html", "dom"}:
        return 2500
    if source_type in {"js", "api", "url", "json", "sourcemap", "service_worker"}:
        return 1000
    return 500


def _navigation_url(document: SourceDocument, matched_text: str) -> str:
    page_url = document.page_url or document.source_url
    if not page_url.startswith(("http://", "https://")):
        return ""
    if document.source_type not in {"html", "dom", "meta", "comment"}:
        return page_url
    clean_match = re.sub(r"\s+", " ", matched_text).strip()
    if not clean_match or len(clean_match) > 120:
        return page_url
    base = page_url.split("#", 1)[0]
    return f"{base}#:~:text={quote(clean_match, safe='')}"


def _display_page_path(value: str) -> str:
    parsed = urlparse(str(value or ""))
    if not parsed.scheme:
        return str(value or "")
    path = parsed.path or "/"
    return f"{path}?{parsed.query}" if parsed.query else path


def _default_element_type(source_type: str) -> str:
    return {
        "api": "API",
        "js": "JavaScript",
        "sourcemap": "SourceMap",
        "css": "CSS",
        "comment": "Comment",
        "cookie": "Cookie",
        "storage": "Storage",
        "meta": "Meta",
        "url": "URL",
        "header": "Headers",
        "robots": "Robots",
        "sitemap": "Sitemap",
    }.get(source_type, "Page")


def _matches_in_text(
    text: str,
    keyword: str,
    variants: list[str],
    modes: list[str],
) -> list[dict[str, Any]]:
    output = []
    spans = set()
    if "exact" in modes:
        for match in re.finditer(re.escape(keyword), text):
            if _overlaps(match.span(), spans):
                continue
            spans.add(match.span())
            output.append(
                {
                    "start": match.start(),
                    "end": match.end(),
                    "variant": keyword,
                    "confidence": "high",
                }
            )
    if "case-insensitive" in modes or "variants" in modes:
        needles = variants if "variants" in modes else [keyword]
        for variant in sorted(set(needles), key=len, reverse=True):
            if not variant:
                continue
            for match in re.finditer(re.escape(variant), text, re.IGNORECASE):
                if _overlaps(match.span(), spans):
                    continue
                spans.add(match.span())
                output.append(
                    {
                        "start": match.start(),
                        "end": match.end(),
                        "variant": variant,
                        "confidence": "high" if variant.casefold() == keyword.casefold() else "medium",
                    }
                )
                if len(output) >= 200:
                    return output
    if "fuzzy" in modes:
        folded = keyword.casefold().lstrip("@")
        for match in WORD_PATTERN.finditer(text):
            token = match.group(0)
            if _overlaps(match.span(), spans) or abs(len(token) - len(keyword)) > 3:
                continue
            ratio = SequenceMatcher(None, token.casefold().lstrip("@"), folded).ratio()
            if ratio < 0.82:
                continue
            spans.add(match.span())
            output.append(
                {
                    "start": match.start(),
                    "end": match.end(),
                    "variant": token,
                    "confidence": "low",
                }
            )
            if len(output) >= 200:
                break
    return output


def _match_risk(document: SourceDocument, surrounding: str) -> tuple[str, str]:
    marker = next(
        (
            item
            for item in SENSITIVE_MARKERS
            if re.search(rf"(?<![\w]){re.escape(item)}(?![\w])", surrounding, re.I)
        ),
        "",
    )
    if marker:
        return "sensitive", f"keyword found within 80 characters of sensitive marker: {marker}"
    if document.source_type in INTERESTING_SOURCES or any(
        marker in document.location.lower()
        for marker in ("href", "route", "script", "network", "storage")
    ):
        return "interesting", f"keyword found in {document.source_type} surface"
    return "info", "keyword found in public page content"


def _build_summary(
    matches: list[dict[str, Any]],
    coverage: Counter[str],
    scan_stats: Counter[str] | None = None,
    page_urls: list[str] | None = None,
) -> dict[str, Any]:
    source_counts = Counter(row["source_type"] for row in matches)
    risk_counts = Counter(row["risk"] for row in matches)
    element_counts = Counter(row.get("element_type") or "Page" for row in matches)
    section_counts = Counter(_section_label(row) for row in matches)
    page_counts: Counter[str] = Counter()
    page_labels: dict[str, str] = {}
    for row in matches:
        url = str(row.get("page_url") or row.get("source_url") or "")
        key = _canonical_url_key(url)
        if key:
            page_counts[key] += 1
            page_labels.setdefault(key, url)
    urls = set(page_counts)
    scanned_pages = {
        _canonical_url_key(str(value))
        for value in (page_urls or [])
        if value
    }
    matched_scanned_pages = {
        value
        for value in urls
        if value in scanned_pages
    }
    source_types = set(source_counts)
    score = min(
        100,
        min(len(source_types) * 6, 30)
        + min(len(urls) * 2, 20)
        + (10 if "js" in source_types else 0)
        + (10 if "api" in source_types else 0)
        + (10 if "oauth" in source_types else 0)
        + (15 if risk_counts.get("sensitive") else 0)
        + (5 if "wayback" in source_types else 0),
    )
    if score >= 75:
        assessment = "High visibility keyword across multiple client-side surfaces."
    elif score >= 45:
        assessment = "Moderate keyword visibility across the site surface."
    elif matches:
        assessment = "Limited keyword visibility was detected."
    else:
        assessment = "No keyword mentions were detected within configured limits."
    return {
        "matches": len(matches),
        "total_occurrences": sum(int(row.get("count") or 1) for row in matches),
        "unique_urls": len(urls),
        "source_types": dict(sorted(source_counts.items())),
        "element_types": dict(sorted(element_counts.items())),
        "sections": dict(section_counts.most_common()),
        "top_pages": [
            {
                "url": page_labels.get(url, url),
                "path": _display_page_path(page_labels.get(url, url)),
                "matches": count,
            }
            for url, count in page_counts.most_common(20)
            if url
        ],
        "pages_scanned": len({_canonical_url_key(value) for value in (page_urls or []) if value}),
        "pages_with_matches": len(matched_scanned_pages),
        "resources_with_matches": len(urls),
        "scan_stats": dict(sorted((scan_stats or {}).items())),
        "risk_counts": {
            "sensitive": risk_counts.get("sensitive", 0),
            "interesting": risk_counts.get("interesting", 0),
            "info": risk_counts.get("info", 0),
        },
        "mention_score": score,
        "assessment": assessment,
        "sources_checked": dict(sorted(coverage.items())),
    }


def _page_results(
    matches: list[dict[str, Any]],
    page_urls: list[str],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    labels: dict[str, str] = {}
    for row in matches:
        page_url = str(row.get("page_url") or row.get("source_url") or "")
        key = _canonical_url_key(page_url)
        if key:
            labels.setdefault(key, page_url)
            grouped.setdefault(key, []).append(row)
    ordered_urls = []
    for page_url in page_urls:
        key = _canonical_url_key(page_url)
        if key and key not in ordered_urls:
            labels.setdefault(key, page_url)
            ordered_urls.append(key)
    for key in grouped:
        if key not in ordered_urls:
            ordered_urls.append(key)
    return [
        {
            "url": labels.get(page_url, page_url),
            "path": _display_page_path(labels.get(page_url, page_url)),
            "matches": len(grouped.get(page_url) or []),
            "occurrences": sum(int(row.get("count") or 1) for row in grouped.get(page_url) or []),
            "sections": dict(
                Counter(
                    _section_label(row)
                    for row in grouped.get(page_url) or []
                ).most_common()
            ),
        }
        for page_url in ordered_urls
    ]


def _section_label(row: dict[str, Any]) -> str:
    section = str(row.get("section") or "").strip()
    if section:
        return section
    return {
        "api": "API",
        "css": "CSS",
        "dom": "Rendered DOM",
        "header": "Response Headers",
        "html": "Page",
        "js": "JavaScript",
        "meta": "Meta",
        "oauth": "OAuth",
        "robots": "Robots",
        "sitemap": "Sitemap",
        "storage": "Storage",
        "url": "URL",
        "comment": "Comments",
        "cookie": "Cookies",
    }.get(str(row.get("source_type") or "").lower(), "Page")


def _fetch_page(
    session: requests.Session,
    url: str,
) -> tuple[requests.Response, bytes] | None:
    response = session.get(
        url,
        timeout=TIMEOUT,
        allow_redirects=True,
        verify=False,
        stream=True,
    )
    content_type = str(response.headers.get("Content-Type") or "").lower()
    if response.status_code >= 500 or "html" not in content_type:
        response.close()
        return None
    return response, _read_response(response)


def _fetch_asset(url: str, source_type: str) -> SourceDocument | None:
    response = requests.get(
        url,
        headers={"User-Agent": USER_AGENT},
        timeout=TIMEOUT,
        allow_redirects=True,
        verify=False,
        stream=True,
    )
    if response.status_code >= 400:
        response.close()
        return None
    body = _read_response(response)
    return SourceDocument(
        source_type,
        response.url,
        f"{source_type} file",
        _decode_body(response, body),
        element_type={
            "js": "JavaScript",
            "css": "CSS",
            "sourcemap": "SourceMap",
            "service_worker": "Service Worker",
        }.get(source_type, "Asset"),
        page_url=response.url,
        target_url=response.url,
    )


def _read_response(response: requests.Response) -> bytes:
    chunks = []
    total = 0
    for chunk in response.iter_content(chunk_size=32_768):
        if not chunk:
            continue
        remaining = MAX_RESPONSE_BYTES - total
        chunks.append(chunk[:remaining])
        total += min(len(chunk), remaining)
        if total >= MAX_RESPONSE_BYTES:
            break
    response.close()
    body = b"".join(chunks)
    setattr(response, "_mention_body", body)
    return body


def _read_cached_body(
    documents: list[SourceDocument],
    url: str,
) -> bytes:
    for document in documents:
        if document.source_url == url and document.location == "response body":
            return document.text.encode("utf-8", errors="ignore")
    return b""


def _decode_body(response: requests.Response, body: bytes) -> str:
    encoding = response.encoding or "utf-8"
    return body.decode(encoding, errors="replace")


def _add_response_documents(
    documents: list[SourceDocument],
    response: requests.Response,
    body: bytes,
    source_type: str,
) -> None:
    if source_type != "html":
        text = _decode_body(response, body)
        documents.append(SourceDocument(source_type, response.url, "response body", text))
    header_text = "\n".join(f"{key}: {value}" for key, value in response.headers.items())
    if header_text:
        documents.append(SourceDocument("header", response.url, "response headers", header_text))
    for cookie in response.cookies:
        documents.append(SourceDocument("cookie", response.url, "cookie:name", cookie.name))


def _parse_html_sources(html: str, base_url: str) -> dict[str, Any]:
    documents = []
    links = []
    js_urls = []
    css_urls = []
    stats: Counter[str] = Counter()
    body = ""
    if not html:
        return {
            "documents": [],
            "links": [],
            "js_urls": [],
            "css_urls": [],
            "stats": {},
            "needs_browser": True,
        }
    try:
        from bs4 import BeautifulSoup, Comment

        soup = BeautifulSoup(html, "html.parser")
        title = soup.title.get_text(" ", strip=True) if soup.title else ""
        if title:
            documents.append(
                SourceDocument(
                    "html",
                    base_url,
                    "Page title",
                    title,
                    element_type="Title",
                    selector="title",
                    xpath="/html/head/title",
                    page_url=base_url,
                    section="Head",
                )
            )
        body = _visible_page_text(soup)
        if body:
            documents.append(
                SourceDocument(
                    "html",
                    base_url,
                    "Page text",
                    body[:MAX_RESPONSE_BYTES],
                    element_type="Page",
                    selector="body",
                    xpath="/html/body",
                    page_url=base_url,
                    section="Page",
                )
            )
        for tag in soup.find_all("meta"):
            value = f"{tag.get('name') or tag.get('property') or ''}: {tag.get('content') or ''}".strip()
            if value:
                documents.append(
                    SourceDocument(
                        "meta",
                        base_url,
                        "Meta",
                        value,
                        element_type="Meta",
                        selector=_bs4_selector(tag),
                        xpath=_bs4_xpath(tag),
                        page_url=base_url,
                        section="Head",
                    )
                )
                stats["meta_scanned"] += 1
        for comment in soup.find_all(string=lambda value: isinstance(value, Comment)):
            documents.append(
                SourceDocument(
                    "comment",
                    base_url,
                    "HTML comment",
                    str(comment),
                    element_type="Comment",
                    page_url=base_url,
                    section="Source",
                )
            )
            stats["comments_scanned"] += 1
        for tag in soup.find_all(href=True):
            href = urljoin(base_url, str(tag.get("href") or ""))
            href = _clean_source_url(href)
            if not href:
                continue
            links.append(href)
            documents.append(
                SourceDocument(
                    "url",
                    base_url,
                    "Link URL",
                    href,
                    element_type="Link",
                    selector=_bs4_selector(tag),
                    xpath=_bs4_xpath(tag),
                    page_url=base_url,
                    section=_bs4_section(tag),
                    target_url=href,
                )
            )
            rel = " ".join(tag.get("rel") or []).lower()
            if tag.name == "link" and "stylesheet" in rel:
                css_urls.append(href)
        semantic_tags = soup.select(
            "button, a, label, input, textarea, select, option, img, form, li, p, "
            "h1, h2, h3, h4, h5, h6, th, td, summary, [role=button], [role=menuitem], "
            "[aria-label], [title], svg title, canvas"
        )
        stats["dom_elements_scanned"] += len(semantic_tags)
        for tag in semantic_tags[:4000]:
            values = [
                tag.get_text(" ", strip=True),
                str(tag.get("aria-label") or ""),
                str(tag.get("placeholder") or ""),
                str(tag.get("title") or ""),
                str(tag.get("alt") or ""),
                str(tag.get("value") or ""),
            ]
            value = " | ".join(_unique_strings(values, 8, case_sensitive=True))
            if not value:
                continue
            element_type = _bs4_element_type(tag)
            stats[_stat_key_for_element(element_type)] += 1
            target_url = ""
            if tag.get("href"):
                target_url = urljoin(base_url, str(tag.get("href")))
            elif tag.get("action"):
                target_url = urljoin(base_url, str(tag.get("action")))
            documents.append(
                SourceDocument(
                    "html",
                    base_url,
                    f"{element_type} {tag.name}",
                    value[:4000],
                    element_type=element_type,
                    selector=_bs4_selector(tag),
                    xpath=_bs4_xpath(tag),
                    page_url=base_url,
                    section=_bs4_section(tag),
                    method=str(tag.get("method") or "").upper(),
                    target_url=target_url,
                )
            )
        for script in soup.find_all("script"):
            src = str(script.get("src") or "")
            if src:
                absolute = urljoin(base_url, src)
                absolute = _clean_source_url(absolute)
                if absolute:
                    js_urls.append(absolute)
                    documents.append(
                        SourceDocument(
                            "url",
                            base_url,
                            "Script URL",
                            absolute,
                            element_type="JavaScript",
                            selector=_bs4_selector(script),
                            xpath=_bs4_xpath(script),
                            page_url=base_url,
                            section="Head" if script.find_parent("head") else "Page",
                            target_url=absolute,
                        )
                    )
                    stats["js_files_scanned"] += 1
            else:
                inline = str(script.string or script.get_text("", strip=False) or "")
                if inline.strip():
                    documents.append(
                        SourceDocument(
                            "js",
                            base_url,
                            "Inline Script",
                            inline[:MAX_RESPONSE_BYTES],
                            element_type="JavaScript",
                            selector=_bs4_selector(script),
                            xpath=_bs4_xpath(script),
                            page_url=base_url,
                            section="Head" if script.find_parent("head") else "Page",
                        )
                    )
                    stats["js_files_scanned"] += 1
    except Exception:
        pass
    return {
        "documents": documents,
        "links": _unique_strings(links, 500),
        "js_urls": _unique_strings(js_urls, 200),
        "css_urls": _unique_strings(css_urls, 100),
        "stats": dict(stats),
        "needs_browser": len(body) < 200 and bool(js_urls),
    }


def _bs4_element_type(tag: Any) -> str:
    name = str(getattr(tag, "name", "") or "").lower()
    context = f"{tag.get('id') or ''} {' '.join(tag.get('class') or [])}".lower()
    if tag.find_parent(["nav"]) or tag.find_parent(attrs={"role": re.compile(r"menu|navigation", re.I)}):
        return "Navigation"
    if name == "button" or str(tag.get("role") or "").lower() == "button":
        return "Button"
    if name == "a":
        return "Link"
    if name == "form":
        return "Form"
    if name in {"input", "textarea", "select", "option"}:
        return "Form Field"
    if name == "label":
        return "Label"
    if name in {"table", "th", "td"}:
        return "Table"
    if name == "li":
        return "List Item"
    if name == "img":
        return "Image"
    if name == "title" and tag.find_parent("svg"):
        return "SVG Title"
    if name == "canvas":
        return "Canvas Fallback"
    if "breadcrumb" in context:
        return "Breadcrumb"
    if "product" in context or "card" in context:
        return "Product Card"
    if re.fullmatch(r"h[1-6]", name):
        return "Heading"
    if name == "p":
        return "Paragraph"
    return "Element"


def _bs4_section(tag: Any) -> str:
    parent = tag.find_parent(["nav", "header", "footer", "aside", "form", "table"])
    if not parent:
        parent = tag.find_parent(attrs={"role": re.compile(r"menu|navigation", re.I)})
    if not parent:
        return "Page"
    name = str(parent.name or "").lower()
    return {
        "nav": "Navigation",
        "header": "Header",
        "footer": "Footer",
        "aside": "Sidebar",
        "form": "Form",
        "table": "Table",
    }.get(name, "Navigation")


def _bs4_selector(tag: Any) -> str:
    parts = []
    current = tag
    while current and getattr(current, "name", None) and len(parts) < 7:
        name = str(current.name).lower()
        element_id = str(current.get("id") or "")
        if element_id:
            parts.insert(0, f"#{_css_escape(element_id)}")
            break
        part = name
        classes = [str(value) for value in (current.get("class") or []) if value][:2]
        if classes:
            part += "." + ".".join(_css_escape(value) for value in classes)
        parent = current.parent
        if parent and getattr(parent, "find_all", None):
            siblings = parent.find_all(name, recursive=False)
            if len(siblings) > 1:
                try:
                    part += f":nth-of-type({siblings.index(current) + 1})"
                except ValueError:
                    pass
        parts.insert(0, part)
        current = parent
        if getattr(current, "name", "") == "html":
            break
    return " > ".join(parts)


def _bs4_xpath(tag: Any) -> str:
    parts = []
    current = tag
    while current and getattr(current, "name", None):
        name = str(current.name).lower()
        parent = current.parent
        index = 1
        if parent and getattr(parent, "find_all", None):
            siblings = parent.find_all(name, recursive=False)
            try:
                index = siblings.index(current) + 1
            except ValueError:
                pass
        parts.insert(0, f"{name}[{index}]")
        current = parent
    return "/" + "/".join(parts)


def _css_escape(value: str) -> str:
    return re.sub(r"([^a-zA-Z0-9_-])", lambda match: f"\\{match.group(1)}", value)


def _stat_key_for_element(element_type: str) -> str:
    return {
        "Button": "buttons_scanned",
        "Link": "links_scanned",
        "Navigation": "navigation_items_scanned",
        "Form": "forms_scanned",
        "Form Field": "form_fields_scanned",
    }.get(element_type, "elements_scanned")


def _append_value_document(
    documents: list[SourceDocument],
    source_type: str,
    source_url: str,
    location: str,
    value: Any,
) -> None:
    if value in (None, "", [], {}):
        return
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, default=str)
        except Exception:
            text = str(value)
    if text:
        if source_type in {"url", "api", "oauth", "cloud", "wayback", "js"}:
            cleaned_url = _clean_source_url(source_url)
            if source_url.startswith(("http://", "https://")) and not cleaned_url:
                return
            source_url = cleaned_url or source_url
        documents.append(
            SourceDocument(
                source_type,
                source_url,
                location,
                text[:MAX_RESPONSE_BYTES],
            )
        )


def _same_host(url: str, host: str) -> bool:
    candidate = (urlparse(str(url or "")).hostname or "").lower()
    return candidate == host or candidate.endswith(f".{host}")


def _is_asset_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith(
        (
            ".js",
            ".css",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".webp",
            ".ico",
            ".woff",
            ".woff2",
            ".ttf",
            ".pdf",
            ".zip",
        )
    )


def _clean_source_url(value: str) -> str:
    raw = str(value or "").strip().strip("\"'`").rstrip("$")
    if not raw.startswith(("http://", "https://", "ws://", "wss://")):
        return raw
    lowered = raw.lower()
    if (
        len(raw) > 300
        or any(char.isspace() for char in raw)
        or any(char in raw for char in "{}()")
        or raw.count("%") > 8
        or any(
            marker in lowered
            for marker in (
                "function",
                "return",
                "=>",
                ");",
                "requestidlecallback",
                "applydomchanges",
                "this._",
                "s.push(",
            )
        )
    ):
        return ""
    return raw


def _compact_context(value: str, limit: int = 80) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[-limit:]


def _unique_strings(
    values: Iterable[Any],
    limit: int,
    case_sensitive: bool = False,
) -> list[str]:
    output = []
    seen = set()
    for value in values:
        raw = str(value or "").strip()
        key = raw if case_sensitive else raw.casefold()
        if not raw or key in seen:
            continue
        seen.add(key)
        output.append(raw)
        if len(output) >= limit:
            break
    return output


def _visible_page_text(soup: Any) -> str:
    hidden_parents = {"head", "script", "style", "noscript", "template"}
    values = []
    for value in soup.stripped_strings:
        parent_name = str(getattr(getattr(value, "parent", None), "name", "") or "").lower()
        if parent_name in hidden_parents:
            continue
        text = re.sub(r"\s+", " ", str(value)).strip()
        if text:
            values.append(text)
    return " ".join(values)


def _canonical_url_key(value: str) -> str:
    parsed = urlparse(str(value or "").strip())
    if not parsed.scheme or not parsed.netloc:
        return str(value or "").split("#", 1)[0].rstrip("/").casefold()
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urlunparse(
        (parsed.scheme.lower(), parsed.netloc.lower(), path, "", parsed.query, "")
    )


def _empty_live_collection(primary_url: str) -> dict[str, Any]:
    return {
        "documents": [],
        "coverage": Counter(),
        "js_urls": [],
        "css_urls": [],
        "primary_url": primary_url,
        "page_urls": [],
        "browser_urls": [],
        "stats": {},
    }


def _safe_collection(
    stage: str,
    operation: Any,
    fallback: Any,
    debug_log: DebugLog | None,
    errors: list[str],
) -> Any:
    try:
        return operation()
    except Exception as exc:
        _record_error(errors, debug_log, f"[MENTION][{stage}]", f"error={type(exc).__name__}: {exc}")
        return fallback


def _overlaps(
    span: tuple[int, int],
    existing: set[tuple[int, int]],
) -> bool:
    start, end = span
    return any(start < other_end and end > other_start for other_start, other_end in existing)


def _record_error(
    errors: list[str],
    debug_log: DebugLog | None,
    prefix: str,
    detail: str,
) -> None:
    message = f"{prefix} {detail}"
    errors.append(message)
    if debug_log:
        try:
            debug_log(message)
        except Exception:
            pass
