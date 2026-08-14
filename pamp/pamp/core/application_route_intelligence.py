from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urljoin, urlparse, urlunparse

from .endpoint_utils import is_noise_url, is_static_asset, normalize_endpoint


ROUTE_CATEGORIES = {
    "public",
    "auth",
    "admin",
    "api",
    "graphql",
    "websocket",
    "upload",
    "download",
    "debug",
    "internal",
    "staging",
    "dev",
    "test",
    "health",
    "metrics",
    "docs",
    "static",
    "unknown",
}
HIGH_INTEREST_KEYWORDS = (
    "admin",
    "administrator",
    "dashboard",
    "internal",
    "debug",
    "dev",
    "test",
    "staging",
    "beta",
    "preview",
    "sandbox",
    "graphql",
    "swagger",
    "openapi",
    "api-docs",
    "metrics",
    "health",
    "actuator",
    "config",
    "settings",
    "users",
    "roles",
    "permissions",
    "billing",
    "invoice",
    "upload",
    "download",
    "backup",
    "export",
    "import",
    "token",
    "oauth",
    "callback",
    "sso",
    "saml",
)
DYNAMIC_IMPORT_KEYWORDS = (
    "admin",
    "dashboard",
    "billing",
    "reports",
    "internal",
    "debug",
    "settings",
    "users",
    "roles",
    "permissions",
    "auth",
    "beta",
    "staging",
    "dev",
    "test",
)
STATIC_ROUTE_EXTENSIONS = (
    ".css",
    ".js",
    ".mjs",
    ".map",
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
    ".eot",
    ".mp4",
    ".webm",
    ".mp3",
    ".pdf",
)
NOISE_PATH_PARTS = (
    "/node_modules/",
    "/vendor/",
    "/vendors/",
    "/webpack/",
    "/__webpack",
)
FRAMEWORK_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("React Router", ("react-router", "createBrowserRouter", "<Route", "useNavigate", "router.push")),
    ("Vue Router", ("vue-router", "createRouter(", "routes:", "beforeEach(")),
    ("Angular Router", ("RouterModule.forRoot", "loadChildren:", "pathMatch", "canActivate")),
    ("Next.js", ("__NEXT_DATA__", "_next/static", "next/dynamic", "dynamic(")),
    ("Nuxt", ("__NUXT__", "_nuxt/", "defineNuxtRouteMiddleware")),
    ("SvelteKit", ("__sveltekit", "load_server_data", "data-sveltekit")),
    ("Vite", ("import.meta.glob", "vite/modulepreload", "/@vite/client")),
    ("Webpack", ("__webpack_require__", "webpackChunk", "chunkName")),
)

MAX_ENDPOINTS = 700
MAX_ROUTES = 500
MAX_JS_ROUTES = 350
MAX_DYNAMIC_IMPORTS = 160
MAX_TREE_CHILDREN = 120
MAX_CONTEXT = 260
MAX_PARAMETERS = 500
MAX_HIDDEN_API_HOSTS = 240
MAX_PERMISSION_MAPPINGS = 180
MAX_CORRELATION_CHAINS = 160
MAX_ROUTE_RISK_CANDIDATES = 180

PARAMETER_CATEGORIES: tuple[tuple[str, frozenset[str]], ...] = (
    ("identifier", frozenset({"id", "user_id", "userid", "account_id", "accountid", "order_id", "orderid", "profile_id", "tenant_id", "customer_id", "invoice_id"})),
    ("auth", frozenset({"token", "access_token", "refresh_token", "code", "state", "scope", "session", "session_id", "jwt", "api_key", "apikey"})),
    ("redirect", frozenset({"url", "redirect", "redirect_uri", "return", "return_url", "next", "callback", "callback_url", "continue", "destination"})),
    ("file", frozenset({"file", "filename", "file_name", "path", "filepath", "download", "document", "attachment"})),
    ("search", frozenset({"q", "query", "search", "keyword", "term", "filter"})),
    ("pagination", frozenset({"page", "limit", "offset", "cursor", "per_page", "pagesize", "page_size"})),
    ("role", frozenset({"role", "roles", "permission", "permissions", "authority", "authorities", "policy", "acl"})),
    ("debug", frozenset({"debug", "admin", "trace", "test", "dev", "preview"})),
)
INTERESTING_PARAMETER_CATEGORIES = {"identifier", "auth", "redirect", "file", "role", "debug"}
PERMISSION_KEYS = {
    "role": "role",
    "roles": "role",
    "isadmin": "role",
    "adminonly": "role",
    "allowedroles": "role",
    "permission": "permission",
    "permissions": "permission",
    "scope": "scope",
    "scopes": "scope",
    "authority": "authority",
    "authorities": "authority",
    "guard": "guard",
    "guards": "guard",
    "canactivate": "guard",
    "requiresauth": "auth",
    "requireauth": "auth",
    "authrequired": "auth",
    "policy": "policy",
    "acl": "acl",
}
HIDDEN_API_HOST_MARKERS = ("api", "internal", "dev", "staging", "beta", "admin", "auth", "gateway", "graphql", "ws", "socket")
CONFIG_URL_RE = re.compile(
    r"\b(?P<key>baseURL|apiUrl|api_url|API_BASE|API_URL|GRAPHQL_URL|WS_URL)\b\s*[:=]\s*(?P<quote>[\"'`])(?P<value>(?:\\.|(?!\2).){1,500})\2",
    re.I | re.S,
)
BODY_OBJECT_RE = re.compile(
    r"\b(?:body\s*:|data\s*:|params\s*:|JSON\.stringify\s*\()\s*\{(?P<body>.{1,900}?)\}",
    re.I | re.S,
)
OBJECT_KEY_RE = re.compile(r"(?:^|[,\s{])(?P<key>[A-Za-z_$][\w$.-]{0,80})\s*:")
APPEND_PARAMETER_RE = re.compile(r"\.(?:append|set)\s*\(\s*(?P<quote>[\"'`])(?P<name>[A-Za-z0-9_.\[\]-]{1,100})\1", re.I)
PATH_PARAMETER_RE = re.compile(r"(?:\{|:|\[)(?P<name>[A-Za-z_][\w-]{0,80})(?:\}|\])")
PERMISSION_HINT_RE = re.compile(
    r"\b(?P<key>role|roles|permission|permissions|guard|guards|canActivate|requiresAuth|requireAuth|authRequired|isAdmin|adminOnly|allowedRoles|scope|scopes|authority|authorities|policy|acl)\b\s*[:=]\s*(?P<value>\[[^\]]{0,300}\]|[\"'`][^\"'`]{0,220}[\"'`]|true|false|[A-Za-z_$][\w$.:/-]{0,180})",
    re.I | re.S,
)

ABSOLUTE_URL_RE = re.compile(r"""(?:https?|wss?)://[^\s"'`<>\\)\]}]{3,360}""", re.I)
STRING_RE = re.compile(r"""(?P<quote>["'`])(?P<value>(?:\\.|(?!\1).){1,700})\1""", re.S)
ROUTE_STRING_RE = re.compile(
    r"""^(?:\.\.?/)?(?:[/#]?[A-Za-z0-9_.~-]+(?:/[A-Za-z0-9_.~:@!$&'()*+,;=%-]+)+|/(?:[A-Za-z0-9_.~:@!$&'()*+,;=%-]+))(?:\?[A-Za-z0-9_.~:@!$&'()*+,;=/%?-]*)?$"""
)
CALL_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("fetch", re.compile(r"""\bfetch\s*\(\s*(?P<quote>["'`])(?P<value>(?:\\.|(?!\1).){1,700})\1""", re.S), "api"),
    (
        "axios",
        re.compile(
            r"""\baxios(?:\.(?P<method>get|post|put|patch|delete|head|options)|\s*)\s*\(\s*(?P<quote>["'`])(?P<value>(?:\\.|(?!\2).){1,700})\2""",
            re.S | re.I,
        ),
        "api",
    ),
    (
        "axios.request",
        re.compile(
            r"""\baxios\.request\s*\(\s*\{(?P<body>.{0,900}?)(?:url|baseURL)\s*:\s*(?P<quote>["'`])(?P<value>(?:\\.|(?!\2).){1,700})\2""",
            re.S | re.I,
        ),
        "api",
    ),
    (
        "XMLHttpRequest.open",
        re.compile(
            r"""\.open\s*\(\s*(?P<mquote>["'`])(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\1\s*,\s*(?P<quote>["'`])(?P<value>(?:\\.|(?!\3).){1,700})\3""",
            re.S | re.I,
        ),
        "api",
    ),
    ("WebSocket", re.compile(r"""\bWebSocket\s*\(\s*(?P<quote>["'`])(?P<value>(?:\\.|(?!\1).){1,700})\1""", re.S), "websocket"),
    ("EventSource", re.compile(r"""\bEventSource\s*\(\s*(?P<quote>["'`])(?P<value>(?:\\.|(?!\1).){1,700})\1""", re.S), "api"),
    ("router.push", re.compile(r"""\brouter\.push\s*\(\s*(?P<quote>["'`])(?P<value>(?:\\.|(?!\1).){1,700})\1""", re.S), "route"),
    ("navigate", re.compile(r"""\bnavigate\s*\(\s*(?P<quote>["'`])(?P<value>(?:\\.|(?!\1).){1,700})\1""", re.S), "route"),
    (
        "history.pushState",
        re.compile(r"""\bhistory\.(?:pushState|replaceState)\s*\([^)]{0,500}?(?P<quote>["'`])(?P<value>/(?:\\.|(?!\1).){1,700})\1""", re.S),
        "route",
    ),
    (
        "window.location",
        re.compile(r"""\b(?:window\.)?location(?:\.href)?\s*=\s*(?P<quote>["'`])(?P<value>(?:\\.|(?!\1).){1,700})\1""", re.S),
        "route",
    ),
    ("window.open", re.compile(r"""\bwindow\.open\s*\(\s*(?P<quote>["'`])(?P<value>(?:\\.|(?!\1).){1,700})\1""", re.S), "route"),
)
DYNAMIC_IMPORT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("import()", re.compile(r"""\bimport\s*\(\s*(?:/\*.*?\*/\s*)?(?P<quote>["'`])(?P<value>(?:\\.|(?!\1).){1,700})\1\s*\)""", re.S)),
    (
        "React.lazy",
        re.compile(
            r"""\bReact\.lazy\s*\(\s*\(?\s*\)?\s*=>\s*import\s*\(\s*(?:/\*.*?\*/\s*)?(?P<quote>["'`])(?P<value>(?:\\.|(?!\1).){1,700})\1\s*\)""",
            re.S,
        ),
    ),
    (
        "Next dynamic",
        re.compile(
            r"""\bdynamic\s*\(\s*\(?\s*\)?\s*=>\s*import\s*\(\s*(?:/\*.*?\*/\s*)?(?P<quote>["'`])(?P<value>(?:\\.|(?!\1).){1,700})\1\s*\)""",
            re.S,
        ),
    ),
    (
        "webpackChunk",
        re.compile(r"""(?P<quote>["'`])(?P<value>[^"'`]{1,220}(?:chunk|lazy|async)[^"'`]{0,220}\.m?js(?:\?[^"'`]*)?)\1""", re.I),
    ),
)
ROUTE_OBJECT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("React/Vue route path", re.compile(r"""\bpath\s*:\s*(?P<quote>["'`])(?P<value>/(?:\\.|(?!\1).){0,500})\1""", re.S)),
    ("route config redirect", re.compile(r"""\bredirect(?:To)?\s*:\s*(?P<quote>["'`])(?P<value>/(?:\\.|(?!\1).){0,500})\1""", re.S)),
    ("menu url", re.compile(r"""\b(?:href|to|url|route)\s*:\s*(?P<quote>["'`])(?P<value>/(?:\\.|(?!\1).){0,500})\1""", re.S)),
)
METHOD_FROM_CONTEXT_RE = re.compile(r"""\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b""", re.I)


def build_application_route_intelligence(data: dict[str, Any], html_text: str = "") -> dict[str, Any]:
    """Recover web application routes from Pamp's passive HTML, JS, DOM, and browser artifacts."""
    base_url = _base_url(data)
    domain = str(data.get("domain") or data.get("host") or urlparse(base_url).hostname or "").lower()
    endpoints: list[dict[str, Any]] = []
    javascript_routes: list[dict[str, Any]] = []
    dynamic_imports: list[dict[str, Any]] = []

    html = data.get("html") or {}
    if html_text:
        endpoints.extend(extract_html_route_sources(html_text, base_url, source_file="http_surface"))
        for route in extract_javascript_routes(_inline_script_text(html_text), base_url, "HTML inline scripts"):
            javascript_routes.append(route)
            endpoints.append(_endpoint_from_js_route(route, base_url))
        dynamic_imports.extend(extract_dynamic_imports(_inline_script_text(html_text), base_url, "HTML inline scripts"))
    endpoints.extend(_endpoints_from_existing(data.get("application_route_intelligence") or {}, base_url))
    javascript_routes.extend(_javascript_routes_from_existing(data.get("application_route_intelligence") or {}))
    dynamic_imports.extend(_dynamic_imports_from_existing(data.get("application_route_intelligence") or {}))
    endpoints.extend(_endpoints_from_html_signals(html, base_url))

    devtools = data.get("devtools") or {}
    endpoints.extend(_endpoints_from_devtools(devtools, base_url))
    endpoints.extend(_endpoints_from_api_sources(data, base_url))
    endpoints.extend(_endpoints_from_discovery(data.get("discovery") or {}, base_url))

    js_analysis = data.get("js_intelligence") or {}
    endpoints.extend(_endpoints_from_js_analysis(js_analysis, base_url))
    for route in _js_routes_from_analysis(js_analysis, base_url):
        javascript_routes.append(route)
        endpoints.append(_endpoint_from_js_route(route, base_url))

    javascript_report = data.get("javascript_intelligence") or {}
    endpoints.extend(_endpoints_from_javascript_report(javascript_report, base_url))

    dynamic_imports.extend(_dynamic_imports_from_html_signals(html, base_url))
    dynamic_imports.extend(_dynamic_imports_from_devtools(devtools, base_url))
    dynamic_imports.extend(_dynamic_imports_from_javascript_report(javascript_report, base_url))

    observed_urls = _observed_url_set(devtools)
    endpoints = _dedupe_endpoints(endpoints, observed_urls)[:MAX_ENDPOINTS]
    javascript_routes = _dedupe_js_routes(javascript_routes, observed_urls)[:MAX_JS_ROUTES]
    dynamic_imports = _dedupe_dynamic_imports(dynamic_imports)[:MAX_DYNAMIC_IMPORTS]

    routes = _build_routes(endpoints, javascript_routes, dynamic_imports, domain)[:MAX_ROUTES]
    route_tree = build_route_tree(routes)
    high_interest_routes = [route for route in routes if route.get("high_interest")][:160]
    insights = _build_insights(routes, endpoints, javascript_routes, dynamic_imports)
    summary = _summary(routes, endpoints, javascript_routes, dynamic_imports, high_interest_routes)

    route_payload = {
        "routes": routes,
        "endpoints": endpoints,
        "javascript_routes": javascript_routes,
        "dynamic_imports": dynamic_imports,
    }
    katana_level_2 = build_katana_level_2(data, route_payload, html_text=html_text)

    return {
        "status": "completed",
        "summary": summary,
        "routes": routes,
        "route_tree": route_tree,
        "endpoints": endpoints,
        "javascript_routes": javascript_routes,
        "dynamic_imports": dynamic_imports,
        "high_interest_routes": high_interest_routes,
        "katana_level_2": katana_level_2,
        "insights": insights,
    }


def extract_html_route_sources(html_text: str, base_url: str, source_file: str = "html") -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not html_text:
        return rows
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_text, "html.parser")
        for tag in soup.find_all("a", href=True):
            _append_endpoint(rows, tag.get("href"), base_url, "HTML link", source_file, "html_link", context=_tag_context(tag))
        for tag in soup.find_all("form"):
            method = str(tag.get("method") or "GET").upper()
            _append_endpoint(rows, tag.get("action") or base_url, base_url, "HTML form", source_file, "form", method=method, context=_tag_context(tag))
        for tag in soup.find_all("script", src=True):
            _append_endpoint(rows, tag.get("src"), base_url, "script src", source_file, "script", context=_tag_context(tag))
        for tag in soup.find_all("link", href=True):
            rel = " ".join(str(item) for item in (tag.get("rel") or [])).lower()
            if any(marker in rel for marker in ("stylesheet", "preload", "prefetch", "modulepreload", "canonical", "manifest")):
                _append_endpoint(rows, tag.get("href"), base_url, f"link {rel or 'href'}", source_file, "link", context=_tag_context(tag))
        for tag in soup.find_all("meta"):
            name = str(tag.get("name") or tag.get("property") or "").lower()
            content = str(tag.get("content") or "")
            if any(marker in name for marker in ("url", "manifest", "sitemap")):
                _append_endpoint(rows, content, base_url, f"HTML meta {name}", source_file, "meta", context=_tag_context(tag))
    except Exception:
        pass
    for match in ABSOLUTE_URL_RE.finditer(html_text):
        _append_endpoint(rows, match.group(0), base_url, "HTML text URL", source_file, "html_text", context=_context(html_text, match.start(), match.end()))
    return _dedupe_endpoints(rows, set())


def extract_javascript_routes(text: str, base_url: str, source_file: str = "javascript") -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    if not text:
        return output
    decoded = _decode_js_text(text)
    framework_hint = _framework_hint(decoded)
    for pattern_name, pattern, source_type in CALL_PATTERNS:
        for match in pattern.finditer(decoded):
            value = _clean_js_literal(match.group("value"))
            method = str(match.groupdict().get("method") or "")
            if not method and pattern_name in {"axios.request"}:
                method = _method_from_context(_context(decoded, match.start(), match.end()))
            if pattern_name == "WebSocket":
                method = "CONNECT"
            _append_js_route(
                output,
                value,
                base_url,
                source_file,
                pattern_name,
                source_type,
                match.start(),
                match.end(),
                decoded,
                method=method.upper(),
                framework_hint=framework_hint,
            )
    for pattern_name, pattern in ROUTE_OBJECT_PATTERNS:
        for match in pattern.finditer(decoded):
            _append_js_route(
                output,
                _clean_js_literal(match.group("value")),
                base_url,
                source_file,
                pattern_name,
                "route_config",
                match.start(),
                match.end(),
                decoded,
                framework_hint=framework_hint,
            )
    for match in STRING_RE.finditer(decoded):
        value = _clean_js_literal(match.group("value"))
        if not _looks_like_route_candidate(value):
            continue
        _append_js_route(
            output,
            value,
            base_url,
            source_file,
            "string literal route",
            "string",
            match.start(),
            match.end(),
            decoded,
            framework_hint=framework_hint,
        )
    for match in ABSOLUTE_URL_RE.finditer(decoded):
        _append_js_route(
            output,
            match.group(0),
            base_url,
            source_file,
            "absolute URL",
            "absolute_url",
            match.start(),
            match.end(),
            decoded,
            framework_hint=framework_hint,
        )
    return _dedupe_js_routes(output, set())


def extract_dynamic_imports(text: str, base_url: str, source_file: str = "javascript") -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    if not text:
        return output
    decoded = _decode_js_text(text)
    framework_hint = _framework_hint(decoded)
    for pattern_name, pattern in DYNAMIC_IMPORT_PATTERNS:
        for match in pattern.finditer(decoded):
            raw = _clean_js_literal(match.group("value"))
            if not raw or _is_noise_route(raw):
                continue
            resolved_url = _resolve_any_url(raw, base_url)
            category = _category_for(raw, source_type="dynamic_import")
            context = _context(decoded, match.start(), match.end())
            output.append(
                {
                    "import_path": raw,
                    "resolved_url": resolved_url,
                    "source_file": source_file,
                    "chunk_name": _chunk_name(raw, context),
                    "framework_hint": _framework_hint(context) or framework_hint,
                    "category": category,
                    "confidence": _confidence("dynamic_import", raw, observed=False),
                    "risk_hint": _risk_hint(raw, category, observed=False),
                    "evidence": context,
                }
            )
    return _dedupe_dynamic_imports(output)


def build_route_tree(routes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    roots: dict[str, dict[str, Any]] = {}
    for route in routes:
        host = str(route.get("host") or "unknown")
        host_node = roots.setdefault(
            host,
            {
                "label": host,
                "path": "/",
                "host": host,
                "category": "host",
                "count": 0,
                "observed": 0,
                "recovered": 0,
                "children": {},
            },
        )
        host_node["count"] += 1
        host_node["observed"] += 1 if route.get("observed") else 0
        host_node["recovered"] += 0 if route.get("observed") else 1
        current = host_node
        path = str(route.get("path") or "/")
        segments = [segment for segment in path.split("/") if segment]
        if not segments:
            segments = ["/"]
        accumulated = ""
        for segment in segments[:12]:
            accumulated = "/" if segment == "/" else f"{accumulated.rstrip('/')}/{segment}"
            children = current.setdefault("children", {})
            child = children.setdefault(
                segment,
                {
                    "label": segment,
                    "path": accumulated,
                    "host": host,
                    "category": route.get("category") or "unknown",
                    "count": 0,
                    "observed": 0,
                    "recovered": 0,
                    "high_interest": False,
                    "children": {},
                },
            )
            child["count"] += 1
            child["observed"] += 1 if route.get("observed") else 0
            child["recovered"] += 0 if route.get("observed") else 1
            child["high_interest"] = bool(child.get("high_interest") or route.get("high_interest"))
            if child.get("category") == "unknown":
                child["category"] = route.get("category") or "unknown"
            current = child

    def finalize(node: dict[str, Any]) -> dict[str, Any]:
        children_map = node.pop("children", {})
        children = sorted(children_map.values(), key=lambda item: (-int(item.get("high_interest") or 0), str(item.get("label") or "")))
        node["children"] = [finalize(child) for child in children[:MAX_TREE_CHILDREN]]
        return node

    return [finalize(node) for node in sorted(roots.values(), key=lambda item: str(item.get("label") or ""))]


def build_katana_level_2(
    data: dict[str, Any],
    route_intelligence: dict[str, Any],
    *,
    html_text: str = "",
) -> dict[str, Any]:
    """Build passive pentest correlations on top of Application Route Intelligence."""
    parameters = extract_parameter_intelligence(data, route_intelligence, html_text=html_text)
    hidden_api_hosts = extract_hidden_api_hosts(data, route_intelligence, html_text=html_text)
    permission_mappings = extract_permission_mappings(data, route_intelligence, html_text=html_text)
    correlation_chains = build_endpoint_correlations(
        route_intelligence,
        parameters,
        permission_mappings,
    )
    route_risk_candidates = build_route_risk_candidates(
        route_intelligence,
        parameters,
        permission_mappings,
        correlation_chains,
    )
    interesting_parameters = sum(1 for row in parameters if row.get("category") in INTERESTING_PARAMETER_CATEGORIES)
    summary = {
        "parameters": len(parameters),
        "interesting_parameters": interesting_parameters,
        "hidden_api_hosts": len({row.get("host") for row in hidden_api_hosts if row.get("host")}),
        "permission_mappings": len(permission_mappings),
        "correlation_chains": len(correlation_chains),
        "route_risk_candidates": len(route_risk_candidates),
    }
    return {
        "status": "completed",
        "summary": summary,
        "parameters": parameters,
        "hidden_api_hosts": hidden_api_hosts,
        "permission_mappings": permission_mappings,
        "correlation_chains": correlation_chains,
        "route_risk_candidates": route_risk_candidates,
        "insights": _katana_level_2_insights(summary, parameters, hidden_api_hosts, route_risk_candidates),
    }


def extract_parameter_intelligence(
    data: dict[str, Any],
    route_intelligence: dict[str, Any],
    *,
    html_text: str = "",
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def add(
        name: Any,
        route: Any,
        location: str,
        source: str,
        source_file: str,
        observed: bool,
        evidence: Any,
    ) -> None:
        clean_name = _clean_parameter_name(name)
        clean_route = str(route or "").strip()
        if not clean_name or _parameter_is_noise(clean_name):
            return
        category = _parameter_category(clean_name)
        rows.append(
            {
                "name": clean_name,
                "route": clean_route,
                "location": location,
                "source": source,
                "source_file": source_file,
                "observed": bool(observed),
                "category": category,
                "confidence": "high" if observed else "medium" if source in {"JavaScript", "API Discovery"} else "low",
                "risk_hint": _parameter_risk_hint(category),
                "evidence": _compact(str(evidence or f"{location} parameter: {clean_name}")),
            }
        )

    url_rows = [
        *as_dict_rows(route_intelligence.get("endpoints")),
        *as_dict_rows(route_intelligence.get("routes")),
        *as_dict_rows(route_intelligence.get("javascript_routes")),
    ]
    for row in url_rows:
        url = str(row.get("absolute_url") or row.get("url") or row.get("path") or "")
        observed = bool(row.get("observed") or row.get("observed_in_network"))
        source_file = str(row.get("source_file") or row.get("source") or "application_route_intelligence")
        for name, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
            add(name, url, "query", "URL", source_file, observed, f"{name}={value}")
        for name in _path_parameter_names(urlparse(url).path):
            add(name, url, "path", "URL", source_file, observed, urlparse(url).path)

    for source_name, forms, observed in (
        ("HTML form", (data.get("html") or {}).get("forms") or [], False),
        ("DOM form", (data.get("devtools") or {}).get("forms") or [], True),
    ):
        for form in forms:
            if not isinstance(form, dict):
                continue
            route = str(form.get("action") or _base_url(data))
            names = [*(form.get("input_names") or []), *(form.get("hidden_input_names") or [])]
            for name in names:
                add(name, route, "form", source_name, source_name.lower().replace(" ", "_"), observed, _compact(str(form)))

    devtools = data.get("devtools") or {}
    for request in devtools.get("network_requests") or []:
        if not isinstance(request, dict):
            continue
        url = str(request.get("url") or "")
        for name, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
            add(name, url, "query", "Observed network request", str(request.get("source_page") or "devtools"), True, f"{name}={value}")
        body = str(request.get("post_data_preview") or "")
        for name in _extract_body_parameter_names(body):
            add(name, url, "body", "Observed network request", str(request.get("source_page") or "devtools"), True, body)
        for header_name in (request.get("request_headers") or {}):
            lowered = str(header_name).lower()
            if lowered == "authorization" or lowered.startswith("x-api-") or lowered.startswith("x-auth-"):
                add(header_name, url, "header", "Observed network request", str(request.get("source_page") or "devtools"), True, header_name)

    for text_source in _katana_text_sources(data, route_intelligence, html_text):
        text = text_source["text"]
        route = text_source["route"]
        for name in _extract_body_parameter_names(text):
            add(name, route, "body", "JavaScript", text_source["source_file"], text_source["observed"], text)
        for match in STRING_RE.finditer(text):
            value = _clean_js_literal(match.group("value"))
            if "?" not in value:
                continue
            resolved = _resolve_any_url(value, _base_url(data))
            for name, parameter_value in parse_qsl(urlparse(resolved).query, keep_blank_values=True):
                add(name, resolved or route, "query", "JavaScript", text_source["source_file"], text_source["observed"], f"{name}={parameter_value}")
        for match in APPEND_PARAMETER_RE.finditer(text):
            add(match.group("name"), route, "body", "JavaScript", text_source["source_file"], text_source["observed"], _context(text, match.start(), match.end()))

    return _dedupe_parameters(rows)[:MAX_PARAMETERS]


def extract_hidden_api_hosts(
    data: dict[str, Any],
    route_intelligence: dict[str, Any],
    *,
    html_text: str = "",
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    base_url = _base_url(data)

    def add(
        value: Any,
        source_file: str,
        source_type: str,
        observed: bool,
        evidence: Any,
        framework_hint: str = "",
    ) -> None:
        url = _resolve_any_url(str(value or ""), base_url)
        if not url or not _looks_like_hidden_api(url, source_type):
            return
        parsed = urlparse(url)
        environment = _environment_hint(url)
        rows.append(
            {
                "host": (parsed.hostname or "").lower(),
                "url": url,
                "path": _normalized_path(parsed.path, parsed.query),
                "source_file": source_file,
                "source_type": source_type,
                "framework_hint": framework_hint,
                "environment_hint": environment,
                "observed": bool(observed),
                "confidence": "high" if observed else "medium",
                "risk_hint": _hidden_api_risk_hint(environment, url),
                "evidence": _compact(str(evidence or value)),
            }
        )

    for row in as_dict_rows(route_intelligence.get("endpoints")):
        add(
            row.get("absolute_url"),
            str(row.get("source_file") or row.get("source") or "application_route_intelligence"),
            str(row.get("source_type") or row.get("category") or "route"),
            bool(row.get("observed")),
            row.get("evidence") or row.get("context"),
        )
    for row in as_dict_rows(route_intelligence.get("javascript_routes")):
        add(
            row.get("absolute_url"),
            str(row.get("source_file") or "javascript"),
            str(row.get("matched_pattern") or "javascript"),
            bool(row.get("observed_in_network")),
            row.get("context"),
            str(row.get("possible_framework") or ""),
        )

    for text_source in _katana_text_sources(data, route_intelligence, html_text):
        text = text_source["text"]
        for match in CONFIG_URL_RE.finditer(text):
            add(match.group("value"), text_source["source_file"], f"config:{match.group('key')}", text_source["observed"], _context(text, match.start(), match.end()), text_source["framework_hint"])
        for match in ABSOLUTE_URL_RE.finditer(text):
            add(match.group(0), text_source["source_file"], text_source["source_type"], text_source["observed"], _context(text, match.start(), match.end()), text_source["framework_hint"])

    merged: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = _route_key(str(row.get("url") or ""))
        current = merged.get(key)
        if current is None:
            merged[key] = row
            continue
        current["observed"] = bool(current.get("observed") or row.get("observed"))
        current["confidence"] = _max_confidence(str(current.get("confidence") or ""), str(row.get("confidence") or ""))
        current["source_type"] = _join_unique(str(current.get("source_type") or ""), str(row.get("source_type") or ""))
        if not current.get("framework_hint"):
            current["framework_hint"] = row.get("framework_hint") or ""
    return sorted(
        merged.values(),
        key=lambda row: (not bool(row.get("environment_hint")), not bool(row.get("observed")), str(row.get("host") or ""), str(row.get("path") or "")),
    )[:MAX_HIDDEN_API_HOSTS]


def extract_permission_mappings(
    data: dict[str, Any],
    route_intelligence: dict[str, Any],
    *,
    html_text: str = "",
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    base_url = _base_url(data)
    for text_source in _katana_text_sources(data, route_intelligence, html_text):
        text = text_source["text"]
        route_candidates = _route_candidates_with_positions(text, base_url)
        source_route = str(text_source.get("route") or "")
        for match in PERMISSION_HINT_RE.finditer(text):
            key = match.group("key").lower()
            value = match.group("value")
            values = _permission_values(key, value)
            if not values:
                continue
            route = _nearest_route(route_candidates, match.start()) or source_route
            if not route:
                continue
            route_path = _normalized_path(urlparse(_resolve_any_url(route, base_url)).path, urlparse(_resolve_any_url(route, base_url)).query)
            evidence = _context(text, match.start(), match.end())
            for permission in values:
                rows.append(
                    {
                        "route": route_path or route,
                        "permission_or_role": permission,
                        "type": PERMISSION_KEYS.get(key, "permission"),
                        "source_file": text_source["source_file"],
                        "framework_hint": text_source["framework_hint"],
                        "confidence": "high" if text_source["observed"] else "medium",
                        "evidence": evidence,
                        "risk_hint": "Protected route candidate; authorization behavior requires manual verification.",
                    }
                )

    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        key = "|".join((str(row.get("route") or "").lower(), str(row.get("type") or "").lower(), str(row.get("permission_or_role") or "").lower(), str(row.get("source_file") or "").lower()))
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return sorted(output, key=lambda row: (str(row.get("route") or ""), str(row.get("type") or ""), str(row.get("permission_or_role") or "")))[:MAX_PERMISSION_MAPPINGS]


def build_endpoint_correlations(
    route_intelligence: dict[str, Any],
    parameters: list[dict[str, Any]],
    permission_mappings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    routes = [row for row in as_dict_rows(route_intelligence.get("routes")) if not row.get("static_asset")]
    endpoints = as_dict_rows(route_intelligence.get("endpoints"))
    js_routes = as_dict_rows(route_intelligence.get("javascript_routes"))
    dynamic_imports = as_dict_rows(route_intelligence.get("dynamic_imports"))
    chains: list[dict[str, Any]] = []

    for route in routes:
        route_url = str(route.get("absolute_url") or route.get("path") or "")
        route_path = str(route.get("path") or urlparse(route_url).path or "/")
        route_key = _correlation_route_key(route_url)
        related_js = [row for row in js_routes if _correlation_route_key(str(row.get("absolute_url") or row.get("path") or "")) == route_key]
        files = _list_unique([str(row.get("source_file") or "") for row in related_js if row.get("source_file")])
        imports = [row for row in dynamic_imports if _import_matches_route(row, route_path, files)]
        involved_endpoints = [row for row in endpoints if _endpoint_matches_route(row, route_path, route_key, files)]
        route_parameters = [row for row in parameters if _correlation_route_key(str(row.get("route") or "")) == route_key]
        permission_hints = [row for row in permission_mappings if _correlation_route_key(str(row.get("route") or "")) == route_key]

        signal_groups = sum(bool(group) for group in (files, imports, involved_endpoints, route_parameters, permission_hints))
        if signal_groups < 2 and not (route.get("high_interest") and signal_groups):
            continue
        involved_files = _list_unique([*files, *[str(row.get("resolved_url") or row.get("import_path") or "") for row in imports]])
        endpoint_urls = _list_unique([str(row.get("absolute_url") or row.get("path") or "") for row in involved_endpoints])
        parameter_names = _list_unique([str(row.get("name") or "") for row in route_parameters])
        permissions = _list_unique([str(row.get("permission_or_role") or "") for row in permission_hints])
        chain = [route_path]
        if files:
            chain.append(files[0])
        if imports:
            chain.append(str(imports[0].get("resolved_url") or imports[0].get("import_path") or "dynamic import"))
        if endpoint_urls:
            chain.append(endpoint_urls[0])
        if parameter_names:
            chain.append("parameters: " + ", ".join(parameter_names[:8]))
        if permissions:
            chain.append("permissions: " + ", ".join(permissions[:6]))
        title, risk_level, note = _correlation_assessment(route, route_parameters, permission_hints, imports)
        chains.append(
            {
                "id": _stable_id("correlation", "|".join(chain)),
                "title": title,
                "chain": chain,
                "involved_routes": [route_path],
                "involved_files": involved_files[:12],
                "involved_endpoints": endpoint_urls[:16],
                "parameters": parameter_names[:20],
                "permission_hints": permissions[:12],
                "confidence": _correlation_confidence(signal_groups, route),
                "risk_level": risk_level,
                "analyst_note": note,
            }
        )
    return sorted(chains, key=lambda row: (-_risk_rank(str(row.get("risk_level") or "")), -len(row.get("chain") or []), str(row.get("title") or "")))[:MAX_CORRELATION_CHAINS]


def build_route_risk_candidates(
    route_intelligence: dict[str, Any],
    parameters: list[dict[str, Any]],
    permission_mappings: list[dict[str, Any]],
    correlation_chains: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    routes = [row for row in as_dict_rows(route_intelligence.get("routes")) if not row.get("static_asset")]
    dynamic_imports = as_dict_rows(route_intelligence.get("dynamic_imports"))
    output: list[dict[str, Any]] = []

    def add(route: dict[str, Any], title: str, risk_level: str, rule: str, signals: list[str], evidence: str) -> None:
        route_value = str(route.get("path") or route.get("absolute_url") or "")
        output.append(
            {
                "id": _stable_id("route-risk", f"{route_value}|{rule}"),
                "title": title,
                "route": route_value,
                "risk_level": risk_level,
                "confidence": "high" if route.get("observed") and len(signals) > 1 else "medium",
                "rule": rule,
                "signals": signals,
                "analyst_note": f"{title} requires manual verification; no vulnerability is asserted.",
                "evidence": _compact(evidence),
            }
        )

    for route in routes:
        route_url = str(route.get("absolute_url") or route.get("path") or "")
        route_path = str(route.get("path") or urlparse(route_url).path or "/")
        key = _correlation_route_key(route_url)
        route_parameters = [row for row in parameters if _correlation_route_key(str(row.get("route") or "")) == key]
        categories = {str(row.get("category") or "") for row in route_parameters}
        names = _list_unique([str(row.get("name") or "") for row in route_parameters])
        names_by_category = {
            name: _list_unique([str(row.get("name") or "") for row in route_parameters if row.get("category") == name])
            for name in categories
        }
        permissions = [row for row in permission_mappings if _correlation_route_key(str(row.get("route") or "")) == key]
        imports = [row for row in dynamic_imports if _import_matches_route(row, route_path, [])]
        category = str(route.get("category") or "")

        if category == "admin" and imports:
            add(route, "High Value Route", "high", "admin route + dynamic import", ["admin route", "dynamic import"], str(imports[0].get("evidence") or imports[0].get("import_path") or ""))
        if "identifier" in categories:
            candidate_names = names_by_category.get("identifier") or names
            add(route, "Potential IDOR Candidate", "high", "route + identifier parameter", candidate_names, ", ".join(candidate_names))
        if "redirect" in categories:
            candidate_names = names_by_category.get("redirect") or names
            add(route, "Open Redirect Candidate", "medium", "route + redirect parameter", candidate_names, ", ".join(candidate_names))
        if "file" in categories:
            candidate_names = names_by_category.get("file") or names
            add(route, "File Access Candidate", "high", "route + file/path parameter", candidate_names, ", ".join(candidate_names))
        if category in {"debug", "dev", "staging", "internal", "test"}:
            add(route, "Hidden/Internal Surface Candidate", "medium", "debug/dev/staging/internal route", [category], route_url)
        if category == "graphql" and route.get("observed"):
            add(route, "GraphQL Surface", "medium", "observed GraphQL route", ["graphql", "observed"], route_url)
        if category == "websocket" and "auth" in categories:
            candidate_names = names_by_category.get("auth") or names
            add(route, "WebSocket Auth Surface", "high", "WebSocket route + auth parameter", candidate_names, ", ".join(candidate_names))
        if permissions:
            permission_values = _list_unique([str(row.get("permission_or_role") or "") for row in permissions])
            add(route, "Protected Route Candidate", "medium", "permission hint + route", permission_values, str(permissions[0].get("evidence") or ""))

    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for row in output:
        key = str(row.get("id") or "")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return sorted(deduped, key=lambda row: (-_risk_rank(str(row.get("risk_level") or "")), str(row.get("route") or ""), str(row.get("title") or "")))[:MAX_ROUTE_RISK_CANDIDATES]


def _endpoints_from_html_signals(html: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    source_map = (
        ("canonical", "canonical", "HTML canonical"),
        ("favicon_url", "link", "HTML favicon"),
        ("script_links", "script", "HTML script src"),
        ("external_js", "script", "HTML external JavaScript"),
        ("external_css", "link", "HTML stylesheet"),
        ("source_map_links", "source_map", "source map reference"),
        ("login_admin_paths", "html_link", "HTML login/admin link"),
        ("api_endpoint_candidates", "html_api", "HTML API candidate"),
        ("social_links", "html_link", "HTML social link"),
    )
    for key, source_type, source in source_map:
        values = html.get(key) or []
        if isinstance(values, str):
            values = [values]
        for value in values:
            _append_endpoint(rows, value, base_url, source, "html", source_type, discovered_from=key)
    for form in html.get("forms") or []:
        if not isinstance(form, dict):
            continue
        _append_endpoint(
            rows,
            form.get("action") or base_url,
            base_url,
            "HTML form",
            "html",
            "form",
            method=str(form.get("method") or "GET").upper(),
            context=", ".join(str(item) for item in form.get("input_names") or [])[:MAX_CONTEXT],
            discovered_from="forms",
        )
    for row in html.get("api_endpoints") or []:
        if isinstance(row, dict):
            _append_endpoint(
                rows,
                row.get("endpoint") or row.get("url") or row.get("value"),
                base_url,
                "HTML API extraction",
                str(row.get("source_file") or "html"),
                "html_api",
                method=str(row.get("method") or ""),
                context=str(row.get("notes") or row.get("evidence") or ""),
                discovered_from="html.api_endpoints",
            )
    return rows


def _endpoints_from_existing(existing: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for endpoint in existing.get("endpoints") or []:
        if not isinstance(endpoint, dict):
            continue
        _append_endpoint(
            rows,
            endpoint.get("absolute_url") or endpoint.get("url") or endpoint.get("endpoint"),
            base_url,
            str(endpoint.get("source") or "previous Application Route Intelligence"),
            str(endpoint.get("source_file") or "application_route_intelligence"),
            str(endpoint.get("source_type") or "previous"),
            method=str(endpoint.get("method") or ""),
            observed=bool(endpoint.get("observed")),
            context=str(endpoint.get("context") or ""),
            evidence=str(endpoint.get("evidence") or ""),
            discovered_from=str(endpoint.get("discovered_from") or "previous"),
        )
    return rows


def _javascript_routes_from_existing(existing: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in existing.get("javascript_routes") or []:
        if isinstance(row, dict) and row.get("absolute_url"):
            rows.append(dict(row))
    return rows


def _dynamic_imports_from_existing(existing: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in existing.get("dynamic_imports") or []:
        if isinstance(row, dict) and (row.get("import_path") or row.get("resolved_url")):
            rows.append(dict(row))
    return rows


def _endpoints_from_devtools(devtools: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for value in devtools.get("dom_links") or []:
        _append_endpoint(rows, value, base_url, "rendered DOM link", "devtools", "dom", observed=True, discovered_from="dom_links")
    for form in devtools.get("forms") or []:
        if not isinstance(form, dict):
            continue
        _append_endpoint(
            rows,
            form.get("action") or base_url,
            base_url,
            "rendered DOM form",
            "devtools",
            "dom_form",
            method=str(form.get("method") or "GET").upper(),
            observed=True,
            context=", ".join(str(item) for item in form.get("input_names") or [])[:MAX_CONTEXT],
            discovered_from="forms",
        )
    for value in devtools.get("loaded_js") or []:
        _append_endpoint(rows, value, base_url, "Playwright loaded JavaScript", "devtools", "script", observed=True, discovered_from="loaded_js")
    for value in devtools.get("loaded_css") or []:
        _append_endpoint(rows, value, base_url, "Playwright loaded stylesheet", "devtools", "link", observed=True, discovered_from="loaded_css")
    for value in devtools.get("websocket_urls") or []:
        _append_endpoint(rows, value, base_url, "Playwright WebSocket", "devtools", "websocket", method="CONNECT", observed=True, discovered_from="websocket_urls")
    for request in devtools.get("network_requests") or []:
        if not isinstance(request, dict):
            continue
        evidence = f"{request.get('method') or 'GET'} {request.get('status') or ''} {request.get('resource_type') or ''}".strip()
        _append_endpoint(
            rows,
            request.get("url"),
            base_url,
            "Playwright network request",
            str(request.get("source_page") or "devtools network"),
            "network",
            method=str(request.get("method") or "GET").upper(),
            observed=True,
            context=evidence,
            evidence=evidence,
            discovered_from="network_requests",
        )
    api = devtools.get("api_intelligence") or {}
    for row in api.get("endpoints") or []:
        if isinstance(row, dict):
            _append_endpoint(
                rows,
                row.get("url") or row.get("endpoint"),
                base_url,
                "DevTools API Intelligence",
                str(row.get("source") or "devtools api"),
                "api_intelligence",
                method=str(row.get("method") or "GET").upper(),
                observed=True,
                context=str(row.get("classification") or row.get("response_type") or ""),
                evidence=str(row.get("classification") or row.get("content_type") or ""),
                discovered_from="api_intelligence",
            )
    for row in devtools.get("graphql_intelligence") or []:
        if isinstance(row, dict):
            _append_endpoint(rows, row.get("endpoint") or row.get("url"), base_url, "DevTools GraphQL", "devtools", "graphql", method=str(row.get("method") or "POST").upper(), observed=True, discovered_from="graphql_intelligence")
    for row in devtools.get("websocket_intelligence") or []:
        if isinstance(row, dict):
            _append_endpoint(rows, row.get("url") or row.get("endpoint"), base_url, "DevTools WebSocket", "devtools", "websocket", method="CONNECT", observed=True, discovered_from="websocket_intelligence")
    js = devtools.get("javascript_intelligence") or {}
    for value in js.get("routes") or js.get("api_endpoints") or []:
        _append_endpoint(rows, value, base_url, "DevTools JavaScript Intelligence", "devtools javascript", "javascript", discovered_from="devtools.javascript_intelligence")
    return rows


def _endpoints_from_api_sources(data: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in ("api_endpoints", "api_endpoint_candidates"):
        for item in data.get(key) or []:
            if isinstance(item, dict):
                _append_endpoint(
                    rows,
                    item.get("endpoint") or item.get("url") or item.get("value"),
                    base_url,
                    "existing API Discovery",
                    str(item.get("source_file") or item.get("source") or key),
                    "api_discovery",
                    method=str(item.get("method") or ""),
                    context=str(item.get("notes") or item.get("evidence") or ""),
                    evidence=str(item.get("notes") or item.get("risk") or ""),
                    discovered_from=key,
                )
            else:
                _append_endpoint(rows, item, base_url, "existing API Discovery", key, "api_discovery", discovered_from=key)
    return rows


def _endpoints_from_discovery(discovery: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in ("findings", "all_results", "api_endpoints"):
        for item in discovery.get(key) or []:
            if not isinstance(item, dict):
                continue
            url = item.get("url") or item.get("endpoint")
            if not url and item.get("path"):
                url = urljoin((discovery.get("base_url") or base_url).rstrip("/") + "/", str(item.get("path") or "").lstrip("/"))
            evidence = f"HTTP {item.get('status_code') or item.get('status') or ''}; {item.get('notes') or ''}".strip()
            _append_endpoint(
                rows,
                url,
                base_url,
                "existing Discovery Engine",
                str(item.get("source_wordlist") or "discovery"),
                "discovery",
                method=str(item.get("method") or "GET").upper(),
                observed=bool(item.get("status_code") or item.get("status")),
                context=evidence,
                evidence=evidence,
                discovered_from=f"discovery.{key}",
            )
    return rows


def _endpoints_from_js_analysis(js_analysis: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in ("api_endpoints", "websockets"):
        for item in js_analysis.get(key) or []:
            if not isinstance(item, dict):
                continue
            _append_endpoint(
                rows,
                item.get("endpoint") or item.get("value") or item.get("url"),
                base_url,
                "JavaScript Route Recovery",
                str(item.get("source_js") or item.get("source") or "javascript"),
                "javascript",
                method=str(item.get("method") or ("CONNECT" if key == "websockets" else "")),
                observed=str(item.get("notes") or "").lower().startswith("observed"),
                context=str(item.get("evidence") or item.get("fragment") or ""),
                evidence=str(item.get("evidence") or item.get("notes") or ""),
                discovered_from=f"js_intelligence.{key}",
            )
    for row in js_analysis.get("graphql") or []:
        if isinstance(row, dict):
            _append_endpoint(rows, row.get("endpoint") or row.get("value"), base_url, "JavaScript GraphQL Recovery", str(row.get("source_js") or row.get("source") or "javascript"), "graphql", method=str(row.get("method") or "POST"), context=str(row.get("evidence") or ""), discovered_from="js_intelligence.graphql")
    return rows


def _endpoints_from_javascript_report(javascript_report: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in javascript_report.get("endpoints") or []:
        if isinstance(row, dict):
            _append_endpoint(rows, row.get("url") or row.get("endpoint"), base_url, "JavaScript report intelligence", str(row.get("source") or "javascript"), "javascript", context=str(row.get("type") or ""), discovered_from="javascript_intelligence.endpoints")
    for row in javascript_report.get("scripts") or []:
        if isinstance(row, dict):
            _append_endpoint(rows, row.get("url"), base_url, "JavaScript asset", str(row.get("source") or "javascript"), "script", observed=str(row.get("status") or "") == "observed", discovered_from="javascript_intelligence.scripts")
    for value in javascript_report.get("source_maps") or []:
        _append_endpoint(rows, value, base_url, "source map reference", "javascript", "source_map", discovered_from="javascript_intelligence.source_maps")
    return rows


def _js_routes_from_analysis(js_analysis: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in (js_analysis.get("api_endpoints") or []) + (js_analysis.get("websockets") or []):
        if not isinstance(item, dict):
            continue
        value = str(item.get("endpoint") or item.get("value") or item.get("url") or "")
        if not value:
            continue
        rows.append(
            _js_route_row(
                value,
                base_url,
                str(item.get("source_js") or item.get("source") or "javascript"),
                str(item.get("type") or "js_intelligence"),
                str(item.get("type") or "api"),
                str(item.get("evidence") or item.get("fragment") or item.get("notes") or ""),
                method=str(item.get("method") or ""),
            )
        )
    for item in js_analysis.get("suspicious_strings") or []:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or "")
        if _looks_like_route_candidate(value):
            rows.append(
                _js_route_row(
                    value,
                    base_url,
                    str(item.get("source_js") or item.get("source") or "javascript"),
                    "suspicious string",
                    "string",
                    str(item.get("evidence") or item.get("notes") or ""),
                )
            )
    return rows


def _dynamic_imports_from_html_signals(html: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in ("script_links", "source_map_links"):
        for value in html.get(key) or []:
            lowered = str(value).lower()
            if key == "source_map_links" or any(marker in lowered for marker in ("chunk", "lazy", "module", "preload", "_next", "_nuxt")):
                rows.append(_dynamic_import_row(str(value), base_url, "html", f"HTML {key}", "HTML asset reference"))
    return rows


def _dynamic_imports_from_devtools(devtools: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for value in (devtools.get("loaded_js") or []) + (devtools.get("loaded_css") or []):
        lowered = str(value).lower()
        if any(marker in lowered for marker in ("chunk", "lazy", "module", "_next", "_nuxt", "vite", "rollup")):
            rows.append(_dynamic_import_row(str(value), base_url, "devtools", "Playwright loaded chunk", "network-loaded chunk"))
    for request in devtools.get("network_requests") or []:
        if not isinstance(request, dict):
            continue
        url = str(request.get("url") or "")
        lowered = url.lower()
        if str(request.get("resource_type") or "").lower() == "script" and any(marker in lowered for marker in ("chunk", "lazy", "module", "_next", "_nuxt", "vite", "rollup")):
            rows.append(_dynamic_import_row(url, base_url, str(request.get("source_page") or "devtools"), "Playwright network chunk", str(request.get("resource_type") or "")))
    return rows


def _dynamic_imports_from_javascript_report(javascript_report: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in javascript_report.get("markers") or []:
        if not isinstance(row, dict):
            continue
        evidence = str(row.get("evidence") or "")
        if "import(" in evidence or "chunk" in evidence.lower():
            rows.extend(extract_dynamic_imports(evidence, base_url, str(row.get("source") or "javascript marker")))
    return rows


def _append_endpoint(
    rows: list[dict[str, Any]],
    raw_value: Any,
    base_url: str,
    source: str,
    source_file: str,
    source_type: str,
    *,
    method: str = "",
    observed: bool = False,
    context: str = "",
    evidence: str = "",
    discovered_from: str = "",
) -> None:
    raw = str(raw_value or "").strip()
    if not raw:
        return
    normalized = _resolve_any_url(raw, base_url)
    if not normalized or _is_noise_route(normalized):
        return
    parsed = urlparse(normalized)
    category = _category_for(normalized, source_type=source_type)
    rows.append(
        {
            "path": _normalized_path(parsed.path, parsed.query),
            "absolute_url": normalized,
            "method": method.upper() if method else "",
            "host": (parsed.hostname or "").lower(),
            "scheme": parsed.scheme,
            "source": source,
            "source_file": source_file,
            "source_type": source_type,
            "context": _compact(context),
            "category": category,
            "confidence": _confidence(source_type, normalized, observed=observed),
            "risk_hint": _risk_hint(normalized, category, observed=observed),
            "evidence": _compact(evidence or context or source),
            "observed": bool(observed),
            "discovered_from": discovered_from or source_type,
        }
    )


def _append_js_route(
    output: list[dict[str, Any]],
    raw: str,
    base_url: str,
    source_file: str,
    matched_pattern: str,
    source_type: str,
    start: int,
    end: int,
    text: str,
    *,
    method: str = "",
    framework_hint: str = "",
) -> None:
    row = _js_route_row(
        raw,
        base_url,
        source_file,
        matched_pattern,
        source_type,
        _context(text, start, end),
        method=method,
        framework_hint=framework_hint,
    )
    if row.get("absolute_url"):
        output.append(row)


def _js_route_row(
    raw: str,
    base_url: str,
    source_file: str,
    matched_pattern: str,
    source_type: str,
    context: str,
    *,
    method: str = "",
    framework_hint: str = "",
) -> dict[str, Any]:
    absolute = _resolve_any_url(raw, base_url)
    if not absolute or _is_noise_route(absolute):
        return {}
    category = _category_for(absolute, source_type=source_type)
    return {
        "path": _normalized_path(urlparse(absolute).path, urlparse(absolute).query),
        "absolute_url": absolute,
        "method": method.upper() if method else "",
        "source_file": source_file,
        "matched_pattern": matched_pattern,
        "confidence": _confidence(source_type, absolute, observed=False),
        "context": _compact(context),
        "reason": _reason_for_js_route(absolute, matched_pattern, source_type),
        "possible_framework": framework_hint,
        "observed_in_network": False,
        "category": category,
    }


def _endpoint_from_js_route(route: dict[str, Any], base_url: str) -> dict[str, Any]:
    absolute = str(route.get("absolute_url") or "")
    parsed = urlparse(absolute)
    category = str(route.get("category") or _category_for(absolute, source_type="javascript"))
    return {
        "path": _normalized_path(parsed.path, parsed.query),
        "absolute_url": absolute,
        "method": str(route.get("method") or ""),
        "host": (parsed.hostname or "").lower(),
        "scheme": parsed.scheme,
        "source": "JavaScript Route Recovery",
        "source_file": str(route.get("source_file") or "javascript"),
        "source_type": "javascript",
        "context": str(route.get("context") or ""),
        "category": category,
        "confidence": str(route.get("confidence") or "medium"),
        "risk_hint": _risk_hint(absolute, category, observed=False),
        "evidence": str(route.get("matched_pattern") or route.get("reason") or ""),
        "observed": False,
        "discovered_from": "javascript_routes",
    }


def _dynamic_import_row(value: str, base_url: str, source_file: str, source: str, evidence: str) -> dict[str, Any]:
    resolved = _resolve_any_url(value, base_url)
    category = _category_for(value, source_type="dynamic_import")
    return {
        "import_path": value,
        "resolved_url": resolved,
        "source_file": source_file,
        "chunk_name": _chunk_name(value, evidence),
        "framework_hint": _framework_hint(f"{value}\n{evidence}"),
        "category": category,
        "confidence": _confidence("dynamic_import", value, observed=source_file == "devtools"),
        "risk_hint": _risk_hint(value, category, observed=source_file == "devtools"),
        "evidence": _compact(f"{source}: {evidence}"),
    }


def _dedupe_endpoints(rows: list[dict[str, Any]], observed_urls: set[str]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for row in rows:
        absolute = str(row.get("absolute_url") or "")
        if not absolute:
            continue
        method = str(row.get("method") or "")
        key = f"{method}|{_route_key(absolute)}"
        current = merged.get(key)
        row = dict(row)
        if _route_key(absolute) in observed_urls:
            row["observed"] = True
        if current is None:
            merged[key] = row
            continue
        current["observed"] = bool(current.get("observed") or row.get("observed"))
        current["confidence"] = _max_confidence(str(current.get("confidence") or ""), str(row.get("confidence") or ""))
        current["risk_hint"] = _stronger_risk(str(current.get("risk_hint") or ""), str(row.get("risk_hint") or ""))
        current["source"] = _join_unique(str(current.get("source") or ""), str(row.get("source") or ""))
        current["source_type"] = _join_unique(str(current.get("source_type") or ""), str(row.get("source_type") or ""))
        current["discovered_from"] = _join_unique(str(current.get("discovered_from") or ""), str(row.get("discovered_from") or ""))
        if not current.get("context"):
            current["context"] = row.get("context") or ""
        if not current.get("evidence"):
            current["evidence"] = row.get("evidence") or ""
    return sorted(
        merged.values(),
        key=lambda item: (
            -_interest_score(str(item.get("absolute_url") or ""), str(item.get("category") or ""), bool(item.get("observed"))),
            str(item.get("host") or ""),
            str(item.get("path") or ""),
        ),
    )


def _dedupe_js_routes(rows: list[dict[str, Any]], observed_urls: set[str]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        absolute = str(row.get("absolute_url") or "")
        if not absolute:
            continue
        key = f"{row.get('source_file')}|{row.get('matched_pattern')}|{_route_key(absolute)}"
        if key in seen:
            continue
        seen.add(key)
        row = dict(row)
        row["observed_in_network"] = _route_key(absolute) in observed_urls
        if row["observed_in_network"]:
            row["confidence"] = _max_confidence(str(row.get("confidence") or ""), "high")
        output.append(row)
    return sorted(
        output,
        key=lambda item: (
            -_interest_score(str(item.get("absolute_url") or ""), str(item.get("category") or ""), bool(item.get("observed_in_network"))),
            str(item.get("source_file") or ""),
        ),
    )


def _dedupe_dynamic_imports(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        key = f"{row.get('source_file')}|{row.get('import_path')}|{row.get('resolved_url')}"
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return sorted(
        output,
        key=lambda item: (
            -_interest_score(str(item.get("resolved_url") or item.get("import_path") or ""), str(item.get("category") or ""), False),
            str(item.get("import_path") or ""),
        ),
    )


def _build_routes(
    endpoints: list[dict[str, Any]],
    javascript_routes: list[dict[str, Any]],
    dynamic_imports: list[dict[str, Any]],
    domain: str,
) -> list[dict[str, Any]]:
    routes: dict[str, dict[str, Any]] = {}
    for endpoint in endpoints:
        absolute = str(endpoint.get("absolute_url") or "")
        if not absolute:
            continue
        parsed = urlparse(absolute)
        key = _route_key(absolute)
        category = str(endpoint.get("category") or _category_for(absolute))
        row = routes.setdefault(
            key,
            {
                "path": _normalized_path(parsed.path, parsed.query),
                "absolute_url": absolute,
                "host": (parsed.hostname or "").lower(),
                "scheme": parsed.scheme,
                "category": category,
                "sources": [],
                "observed": False,
                "recovered": False,
                "static_asset": _is_static_application_asset(absolute),
                "high_interest": False,
                "risk_hint": "",
                "confidence": "low",
                "evidence_count": 0,
            },
        )
        row["sources"] = _list_unique([*row.get("sources", []), str(endpoint.get("source_type") or endpoint.get("source") or "")])
        row["observed"] = bool(row.get("observed") or endpoint.get("observed"))
        row["recovered"] = bool(row.get("recovered") or not endpoint.get("observed"))
        row["confidence"] = _max_confidence(str(row.get("confidence") or ""), str(endpoint.get("confidence") or ""))
        row["risk_hint"] = _stronger_risk(str(row.get("risk_hint") or ""), str(endpoint.get("risk_hint") or ""))
        row["evidence_count"] = int(row.get("evidence_count") or 0) + 1
        row["high_interest"] = bool(row.get("high_interest") or _is_high_interest(absolute, category))
        if row.get("category") in {"unknown", "public"} and category not in {"unknown", "public"}:
            row["category"] = category
    for js_route in javascript_routes:
        absolute = str(js_route.get("absolute_url") or "")
        key = _route_key(absolute)
        if not key:
            continue
        parsed = urlparse(absolute)
        category = str(js_route.get("category") or _category_for(absolute, source_type="javascript"))
        row = routes.setdefault(
            key,
            {
                "path": _normalized_path(parsed.path, parsed.query),
                "absolute_url": absolute,
                "host": (parsed.hostname or "").lower(),
                "scheme": parsed.scheme,
                "category": category,
                "sources": [],
                "observed": False,
                "recovered": True,
                "static_asset": _is_static_application_asset(absolute),
                "high_interest": False,
                "risk_hint": "",
                "confidence": "low",
                "evidence_count": 0,
            },
        )
        row["sources"] = _list_unique([*row.get("sources", []), "javascript"])
        row["observed"] = bool(row.get("observed") or js_route.get("observed_in_network"))
        row["recovered"] = True
        row["confidence"] = _max_confidence(str(row.get("confidence") or ""), str(js_route.get("confidence") or ""))
        row["risk_hint"] = _stronger_risk(str(row.get("risk_hint") or ""), _risk_hint(absolute, category, bool(row.get("observed"))))
        row["evidence_count"] = int(row.get("evidence_count") or 0) + 1
        row["high_interest"] = bool(row.get("high_interest") or _is_high_interest(absolute, category))
    for dynamic_import in dynamic_imports:
        absolute = str(dynamic_import.get("resolved_url") or "")
        if not absolute:
            continue
        parsed = urlparse(absolute)
        key = _route_key(absolute)
        category = str(dynamic_import.get("category") or _category_for(absolute, source_type="dynamic_import"))
        row = routes.setdefault(
            key,
            {
                "path": _normalized_path(parsed.path, parsed.query),
                "absolute_url": absolute,
                "host": (parsed.hostname or "").lower(),
                "scheme": parsed.scheme,
                "category": category,
                "sources": [],
                "observed": False,
                "recovered": True,
                "static_asset": True,
                "high_interest": False,
                "risk_hint": "",
                "confidence": "low",
                "evidence_count": 0,
            },
        )
        row["sources"] = _list_unique([*row.get("sources", []), "dynamic_import"])
        row["recovered"] = True
        row["confidence"] = _max_confidence(str(row.get("confidence") or ""), str(dynamic_import.get("confidence") or ""))
        row["risk_hint"] = _stronger_risk(str(row.get("risk_hint") or ""), str(dynamic_import.get("risk_hint") or ""))
        row["evidence_count"] = int(row.get("evidence_count") or 0) + 1
        row["high_interest"] = bool(row.get("high_interest") or _is_high_interest(absolute, category) or _dynamic_import_high_interest(dynamic_import))
    rows = list(routes.values())
    for row in rows:
        host = str(row.get("host") or "")
        row["same_site"] = bool(domain and host and (host == domain or host.endswith(f".{domain}")))
        if not row.get("risk_hint"):
            row["risk_hint"] = _risk_hint(str(row.get("absolute_url") or ""), str(row.get("category") or ""), bool(row.get("observed")))
    return sorted(
        rows,
        key=lambda item: (
            -_interest_score(str(item.get("absolute_url") or ""), str(item.get("category") or ""), bool(item.get("observed"))),
            str(item.get("host") or ""),
            str(item.get("path") or ""),
        ),
    )


def _summary(
    routes: list[dict[str, Any]],
    endpoints: list[dict[str, Any]],
    javascript_routes: list[dict[str, Any]],
    dynamic_imports: list[dict[str, Any]],
    high_interest_routes: list[dict[str, Any]],
) -> dict[str, int]:
    return {
        "total_routes": len(routes),
        "observed_routes": sum(1 for row in routes if row.get("observed")),
        "recovered_routes": sum(1 for row in routes if not row.get("observed")),
        "api_routes": sum(1 for row in routes if row.get("category") == "api"),
        "admin_routes": sum(1 for row in routes if row.get("category") == "admin"),
        "auth_routes": sum(1 for row in routes if row.get("category") == "auth"),
        "graphql_routes": sum(1 for row in routes if row.get("category") == "graphql"),
        "websocket_routes": sum(1 for row in routes if row.get("category") == "websocket"),
        "hidden_routes": sum(1 for row in routes if not row.get("observed") and not row.get("static_asset")),
        "dynamic_imports": len(dynamic_imports),
        "js_recovered_routes": len(javascript_routes),
        "high_interest": len(high_interest_routes),
        "endpoints": len(endpoints),
    }


def _build_insights(
    routes: list[dict[str, Any]],
    endpoints: list[dict[str, Any]],
    javascript_routes: list[dict[str, Any]],
    dynamic_imports: list[dict[str, Any]],
) -> list[dict[str, str]]:
    insights: list[dict[str, str]] = []
    js_admin = [row for row in javascript_routes if row.get("category") in {"admin", "internal", "debug"}]
    if js_admin:
        insights.append(_insight("Client-side JavaScript references administrative or internal routes.", "medium", "high", f"{len(js_admin)} recovered route(s) require manual verification."))
    sensitive_imports = [row for row in dynamic_imports if _dynamic_import_high_interest(row)]
    if sensitive_imports:
        insights.append(_insight("Dynamic imports reference potentially sensitive application modules.", "medium", "medium", f"{len(sensitive_imports)} lazy-loaded module reference(s) recovered."))
    api_recovered = [row for row in javascript_routes if row.get("category") in {"api", "graphql"}]
    if len(api_recovered) >= 3:
        insights.append(_insight("Multiple API routes were recovered from JavaScript bundles.", "low", "high", f"{len(api_recovered)} JavaScript API route(s) recovered."))
    websocket_routes = [row for row in routes if row.get("category") == "websocket"]
    if websocket_routes:
        insights.append(_insight("WebSocket endpoints were discovered.", "medium", "high" if any(row.get("observed") for row in websocket_routes) else "medium", f"{len(websocket_routes)} WebSocket route(s) observed or recovered."))
    hidden = [row for row in routes if not row.get("observed") and row.get("category") in {"debug", "internal", "admin", "staging", "dev", "test"}]
    if hidden:
        insights.append(_insight("Hidden or debug-like routes were referenced in client-side data.", "medium", "medium", f"{len(hidden)} recovered route(s) were not observed in browser navigation."))
    spa_hints = [row for row in javascript_routes if row.get("possible_framework") or row.get("matched_pattern") in {"router.push", "navigate", "React/Vue route path"}]
    if len(spa_hints) >= 2:
        insights.append(_insight("Route structure suggests SPA client-side routing.", "info", "medium", f"{len(spa_hints)} router/navigation evidence item(s) recovered."))
    unobserved = [row for row in javascript_routes if not row.get("observed_in_network")]
    if unobserved:
        insights.append(_insight("Some recovered routes were not observed during browser navigation and require manual verification.", "info", "medium", f"{len(unobserved)} JavaScript route(s) are recovered-only."))
    endpoint_categories = Counter(str(row.get("category") or "unknown") for row in endpoints)
    if endpoint_categories.get("graphql"):
        insights.append(_insight("GraphQL routes were referenced or observed.", "medium", "medium", f"{endpoint_categories['graphql']} GraphQL endpoint evidence item(s)."))
    return insights[:12]


def _insight(title: str, risk: str, confidence: str, detail: str) -> dict[str, str]:
    return {"title": title, "risk": risk, "confidence": confidence, "detail": detail}


def _katana_level_2_insights(
    summary: dict[str, int],
    parameters: list[dict[str, Any]],
    hidden_api_hosts: list[dict[str, Any]],
    route_risk_candidates: list[dict[str, Any]],
) -> list[dict[str, str]]:
    insights: list[dict[str, str]] = []
    if summary.get("interesting_parameters"):
        categories = Counter(str(row.get("category") or "unknown") for row in parameters if row.get("category") in INTERESTING_PARAMETER_CATEGORIES)
        top = ", ".join(f"{name}: {count}" for name, count in categories.most_common(4))
        insights.append(_insight("Interesting parameters require review", "medium", "medium", top))
    environment_hosts = sorted({str(row.get("host") or "") for row in hidden_api_hosts if row.get("environment_hint")})
    if environment_hosts:
        insights.append(_insight("Non-production or internal API naming recovered", "medium", "medium", ", ".join(environment_hosts[:8])))
    high_risk = sum(1 for row in route_risk_candidates if row.get("risk_level") == "high")
    if high_risk:
        insights.append(_insight("High-value route candidates identified", "high", "medium", f"{high_risk} candidate(s); each requires manual verification."))
    return insights[:8]


def _katana_text_sources(
    data: dict[str, Any],
    route_intelligence: dict[str, Any],
    html_text: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def add(
        value: Any,
        source_file: Any,
        source_type: str,
        *,
        observed: bool = False,
        route: Any = "",
        framework_hint: Any = "",
    ) -> None:
        text = str(value or "").strip()
        if not text:
            return
        rows.append(
            {
                "text": text[:6000],
                "source_file": str(source_file or source_type),
                "source_type": source_type,
                "observed": bool(observed),
                "route": str(route or ""),
                "framework_hint": str(framework_hint or _framework_hint(text)),
            }
        )

    if html_text:
        add(_inline_script_text(html_text), "HTML inline scripts", "inline_javascript")
    for row in as_dict_rows(route_intelligence.get("javascript_routes")):
        add(
            "\n".join(str(row.get(key) or "") for key in ("context", "reason", "absolute_url")),
            row.get("source_file"),
            "javascript_route",
            observed=bool(row.get("observed_in_network")),
            route=row.get("absolute_url") or row.get("path"),
            framework_hint=row.get("possible_framework"),
        )
    for row in as_dict_rows(route_intelligence.get("endpoints")):
        add(
            "\n".join(str(row.get(key) or "") for key in ("context", "evidence", "absolute_url")),
            row.get("source_file") or row.get("source"),
            str(row.get("source_type") or "endpoint"),
            observed=bool(row.get("observed")),
            route=row.get("absolute_url") or row.get("path"),
        )
    for row in as_dict_rows(route_intelligence.get("dynamic_imports")):
        add(
            "\n".join(str(row.get(key) or "") for key in ("evidence", "import_path", "resolved_url")),
            row.get("source_file"),
            "dynamic_import",
            route=row.get("resolved_url") or row.get("import_path"),
            framework_hint=row.get("framework_hint"),
        )

    js_intelligence = data.get("js_intelligence") or {}
    for key in ("api_endpoints", "graphql", "websockets", "config_objects", "suspicious_strings"):
        for row in as_dict_rows(js_intelligence.get(key)):
            add(
                "\n".join(str(row.get(field) or "") for field in ("value", "endpoint", "url", "evidence", "fragment", "notes")),
                row.get("source_js") or row.get("source"),
                f"js_intelligence.{key}",
                route=row.get("endpoint") or row.get("url") or row.get("value") if key in {"api_endpoints", "graphql", "websockets"} else "",
            )
    javascript_report = data.get("javascript_intelligence") or {}
    for key in ("markers", "endpoints"):
        for row in as_dict_rows(javascript_report.get(key)):
            add(
                "\n".join(str(row.get(field) or "") for field in ("url", "evidence", "type")),
                row.get("source"),
                f"javascript_intelligence.{key}",
                route=row.get("url"),
            )
    devtools_js = (data.get("devtools") or {}).get("javascript_intelligence") or {}
    for key in ("api_endpoints", "graphql_endpoints", "websocket_urls", "routes", "findings"):
        values = devtools_js.get(key) or []
        for row in values[:160]:
            if isinstance(row, dict):
                add(
                    "\n".join(str(row.get(field) or "") for field in ("value", "url", "route", "evidence", "detail")),
                    row.get("source") or "devtools javascript",
                    f"devtools.javascript.{key}",
                    observed=True,
                    route=row.get("url") or row.get("route") or row.get("value"),
                )
            else:
                add(row, "devtools javascript", f"devtools.javascript.{key}", observed=True, route=row)
    return rows[:900]


def _extract_body_parameter_names(text: str) -> list[str]:
    value = str(text or "").strip()
    if not value:
        return []
    names: list[str] = []
    if value.startswith("{") and value.endswith("}"):
        try:
            payload = json.loads(value)
            if isinstance(payload, dict):
                names.extend(str(key) for key in payload)
        except (TypeError, ValueError):
            pass
    if "=" in value and "{" not in value[:20]:
        names.extend(name for name, _ in parse_qsl(value, keep_blank_values=True))
    for match in BODY_OBJECT_RE.finditer(value):
        names.extend(key_match.group("key") for key_match in OBJECT_KEY_RE.finditer(match.group("body")))
    names.extend(match.group("name") for match in APPEND_PARAMETER_RE.finditer(value))
    return _list_unique([_clean_parameter_name(name) for name in names if name])[:80]


def _clean_parameter_name(value: Any) -> str:
    name = unquote(str(value or "")).strip().strip("[]{}:$").lower()
    name = re.sub(r"\[\]$", "", name)
    return name[:100]


def _parameter_is_noise(name: str) -> bool:
    if not name or len(name) > 100 or not re.fullmatch(r"[a-z_][a-z0-9_.\[\]-]*", name, re.I):
        return True
    return name in {"_", "cb", "cachebuster", "method", "headers", "body", "data", "params", "credentials", "mode", "cache", "signal", "referrer", "integrity", "keepalive"}


def _parameter_category(name: str) -> str:
    normalized = name.lower().replace("-", "_").replace(".", "_")
    tail = normalized.rsplit("_", 1)[-1]
    for category, values in PARAMETER_CATEGORIES:
        if normalized in values or (category == "identifier" and tail == "id"):
            return category
    return "unknown"


def _parameter_risk_hint(category: str) -> str:
    return {
        "identifier": "Potential IDOR candidate; requires manual verification.",
        "auth": "Authentication/session parameter; requires manual verification.",
        "redirect": "Open redirect candidate; requires manual verification.",
        "file": "File access candidate; requires manual verification.",
        "role": "Permission manipulation candidate; requires manual verification.",
        "debug": "Hidden/debug behavior candidate; requires manual verification.",
    }.get(category, "Parameter behavior requires manual verification.")


def _path_parameter_names(path: str) -> list[str]:
    return _list_unique([match.group("name") for match in PATH_PARAMETER_RE.finditer(str(path or ""))])


def _dedupe_parameters(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = "|".join(
            (
                str(row.get("name") or "").lower(),
                _correlation_route_key(str(row.get("route") or "")),
                str(row.get("location") or "").lower(),
                str(row.get("source_file") or "").lower(),
            )
        )
        current = merged.get(key)
        if current is None:
            merged[key] = row
            continue
        current["observed"] = bool(current.get("observed") or row.get("observed"))
        current["confidence"] = _max_confidence(str(current.get("confidence") or ""), str(row.get("confidence") or ""))
        current["source"] = _join_unique(str(current.get("source") or ""), str(row.get("source") or ""))
    return sorted(
        merged.values(),
        key=lambda row: (
            0 if row.get("category") in INTERESTING_PARAMETER_CATEGORIES else 1,
            not bool(row.get("observed")),
            str(row.get("route") or ""),
            str(row.get("name") or ""),
        ),
    )


def _looks_like_hidden_api(url: str, source_type: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    host_parts = [part for part in host.split(".") if part]
    host_match = any(part in HIDDEN_API_HOST_MARKERS for part in host_parts)
    path_match = any(marker in path for marker in ("/api", "/graphql", "/gql", "/ws", "/socket", "/internal", "/gateway"))
    source_match = any(marker in str(source_type or "").lower() for marker in ("api", "graphql", "websocket", "config:"))
    return bool(host and (host_match or path_match or source_match))


def _environment_hint(value: str) -> str:
    lowered = str(value or "").lower()
    for marker in ("internal", "staging", "dev", "beta", "test", "admin", "auth", "gateway", "graphql", "ws", "socket", "api"):
        if re.search(rf"(?:^|[./_-]){re.escape(marker)}(?:[./_:-]|$)", lowered):
            return marker
    return ""


def _hidden_api_risk_hint(environment: str, url: str) -> str:
    if environment in {"internal", "staging", "dev", "beta", "test"}:
        return "Hidden/internal API surface candidate; requires manual verification."
    if "graphql" in str(url).lower():
        return "GraphQL API surface candidate; requires manual verification."
    if str(url).lower().startswith(("ws://", "wss://")):
        return "WebSocket API surface candidate; requires manual verification."
    return "Recovered API surface; requires manual verification."


def _route_candidates_with_positions(text: str, base_url: str) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    for match in STRING_RE.finditer(text):
        value = _clean_js_literal(match.group("value"))
        if not _looks_like_route_candidate(value):
            continue
        resolved = _resolve_any_url(value, base_url)
        path = _normalized_path(urlparse(resolved).path, urlparse(resolved).query)
        if path:
            rows.append((match.start(), path))
    return rows


def _nearest_route(candidates: list[tuple[int, str]], position: int) -> str:
    nearby = [(abs(index - position), route) for index, route in candidates if abs(index - position) <= 700]
    return min(nearby, default=(0, ""), key=lambda item: item[0])[1]


def _permission_values(key: str, raw_value: str) -> list[str]:
    lowered_key = key.lower()
    value = str(raw_value or "").strip()
    if value.lower() == "false":
        return []
    if value.lower() == "true":
        if lowered_key in {"isadmin", "adminonly"}:
            return ["admin"]
        if lowered_key in {"requiresauth", "requireauth", "authrequired"}:
            return ["authenticated"]
        return [lowered_key]
    tokens = re.findall(r"[A-Za-z0-9_.:*:/-]{1,120}", value)
    return _list_unique([token for token in tokens if token.lower() not in {"true", "false", "null", "undefined"}])[:20]


def _correlation_route_key(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlparse(text if "://" in text else f"https://local.invalid/{text.lstrip('/')}")
    path = re.sub(r"/+", "/", parsed.path or "/").rstrip("/") or "/"
    return path.lower()


def _route_terms(path: str) -> set[str]:
    return {
        item.lower()
        for item in re.split(r"[^A-Za-z0-9]+", str(path or ""))
        if len(item) >= 4 and item.lower() not in {"https", "http", "static", "assets", "index", "module", "modules"}
    }


def _import_matches_route(row: dict[str, Any], route_path: str, source_files: list[str]) -> bool:
    source_file = str(row.get("source_file") or "")
    if source_file and source_file in source_files:
        return True
    route_terms = _route_terms(route_path)
    import_terms = _route_terms(str(row.get("import_path") or row.get("resolved_url") or row.get("chunk_name") or ""))
    return bool(route_terms & import_terms)


def _endpoint_matches_route(
    row: dict[str, Any],
    route_path: str,
    route_key: str,
    source_files: list[str],
) -> bool:
    endpoint_url = str(row.get("absolute_url") or row.get("path") or "")
    if _correlation_route_key(endpoint_url) == route_key:
        return True
    source_file = str(row.get("source_file") or "")
    if source_file and source_file in source_files:
        return True
    return bool(_route_terms(route_path) & _route_terms(urlparse(endpoint_url).path))


def _correlation_assessment(
    route: dict[str, Any],
    parameters: list[dict[str, Any]],
    permissions: list[dict[str, Any]],
    imports: list[dict[str, Any]],
) -> tuple[str, str, str]:
    categories = {str(row.get("category") or "") for row in parameters}
    route_category = str(route.get("category") or "")
    if route_category == "admin" or permissions:
        return "High Value Admin Surface" if route_category == "admin" else "Protected Route Correlation", "high", "Authorization and route relationships require manual verification."
    if "identifier" in categories:
        return "Potential IDOR Candidate", "high", "Identifier-to-endpoint behavior requires manual authorization testing."
    if "file" in categories:
        return "File Access Candidate", "high", "File/path parameter handling requires manual verification."
    if "redirect" in categories:
        return "Open Redirect Candidate", "medium", "Redirect target validation requires manual verification."
    if imports:
        return "Lazy-loaded Application Surface", "medium", "Recovered module relationships may expose additional routes for manual review."
    return "Route and Endpoint Correlation", "low", "Passive evidence links this route to application endpoints."


def _correlation_confidence(signal_groups: int, route: dict[str, Any]) -> str:
    if route.get("observed") and signal_groups >= 3:
        return "high"
    if signal_groups >= 2:
        return "medium"
    return "low"


def _stable_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(str(value or "").encode("utf-8", errors="ignore")).hexdigest()[:16]
    return f"{prefix}:{digest}"


def _risk_rank(value: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "warning": 2, "low": 1, "info": 0}.get(str(value or "").lower(), 0)


def as_dict_rows(value: Any) -> list[dict[str, Any]]:
    return [row for row in (value or []) if isinstance(row, dict)]


def _base_url(data: dict[str, Any]) -> str:
    http = data.get("http") or {}
    surface = data.get("http_surface") or {}
    devtools = data.get("devtools") or {}
    return str(
        devtools.get("final_url")
        or surface.get("final_url")
        or surface.get("primary_url")
        or http.get("final_url")
        or http.get("url")
        or (f"https://{data.get('domain') or data.get('host')}" if (data.get("domain") or data.get("host")) else "")
    )


def _resolve_any_url(value: str, base_url: str) -> str:
    raw = _clean_js_literal(str(value or ""))
    if not raw:
        return ""
    raw = raw.replace("&amp;", "&")
    if raw.startswith(("mailto:", "tel:", "javascript:", "data:", "blob:")):
        return ""
    if raw.startswith("#"):
        raw = "/" + raw.lstrip("#")
    if raw.startswith(("ws://", "wss://")):
        return normalize_endpoint(raw, base_url) or raw
    normalized = normalize_endpoint(raw, base_url)
    if normalized:
        return normalized
    if base_url and raw.startswith(("./", "../", "/")):
        candidate = urljoin(base_url, raw)
        normalized = normalize_endpoint(candidate, base_url)
        if normalized:
            return normalized
        if _is_static_application_asset(candidate):
            parsed = urlparse(candidate)
            if parsed.scheme in {"http", "https", "ws", "wss"} and parsed.netloc:
                return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))
    if raw.startswith(("http://", "https://", "ws://", "wss://")) and _is_static_application_asset(raw):
        parsed = urlparse(raw)
        if parsed.scheme and parsed.netloc:
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))
    return ""


def _normalized_path(path: str, query: str = "") -> str:
    clean_path = "/" + "/".join(segment for segment in unquote(path or "/").split("/") if segment)
    if path == "/" or not path:
        clean_path = "/"
    return f"{clean_path}?{query}" if query else clean_path


def _route_key(value: str) -> str:
    parsed = urlparse(str(value or ""))
    if not parsed.scheme or not parsed.netloc:
        return ""
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", parsed.query, ""))


def _category_for(value: str, source_type: str = "") -> str:
    lowered_all = f"{value} {source_type}".lower()
    parsed = urlparse(value if "://" in value else f"https://placeholder.local/{value.lstrip('/')}")
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    lowered = f"{parsed.path} {parsed.query} {source_type}".lower()
    if value.lower().startswith(("ws://", "wss://")) or "websocket" in lowered_all:
        return "websocket"
    if "graphql" in lowered_all or "/gql" in path:
        return "graphql"
    if source_type in {"script", "link", "source_map"}:
        return "static"
    if host.startswith("api.") or ".api." in host:
        return "api"
    category_markers: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("admin", ("admin", "administrator", "wp-admin")),
        ("auth", ("auth", "oauth", "oidc", "login", "logout", "signin", "signout", "session", "sso", "saml", "callback")),
        ("api", ("api", "rest", "ajax", "rpc", "v1", "v2", "v3")),
        ("upload", ("upload", "import")),
        ("download", ("download", "export", "backup")),
        ("debug", ("debug", "trace", "profiler")),
        ("internal", ("internal", "private", "intranet")),
        ("staging", ("staging", "stage", "preview", "sandbox", "beta")),
        ("dev", ("dev", "development", "local")),
        ("test", ("test", "testing", "qa")),
        ("health", ("health", "status", "ping", "ready", "live")),
        ("metrics", ("metrics", "prometheus", "actuator")),
        ("docs", ("swagger", "openapi", "api-docs", "redoc", "docs")),
    )
    segments = [segment for segment in re.split(r"[^a-z0-9]+", lowered) if segment]
    for category, markers in category_markers:
        if any(_has_route_marker(lowered, segments, marker) for marker in markers):
            return category
    if _is_static_application_asset(value):
        return "static"
    if path in {"", "/"}:
        return "public"
    return "unknown"


def _has_route_marker(lowered: str, segments: list[str], marker: str) -> bool:
    marker = marker.lower()
    if marker in segments:
        return True
    if len(marker) <= 4:
        return any(token in lowered for token in (f"/{marker}/", f"/{marker}?", f"/{marker}.", f"-{marker}", f"_{marker}"))
    return marker in lowered


def _confidence(source_type: str, value: str, *, observed: bool) -> str:
    if observed or source_type in {"network", "dom", "dom_form", "api_intelligence"}:
        return "high"
    if source_type in {"fetch", "api", "websocket", "graphql", "form", "discovery", "javascript", "dynamic_import"}:
        return "medium"
    if value.startswith(("http://", "https://", "ws://", "wss://", "/")):
        return "medium"
    return "low"


def _risk_hint(value: str, category: str, observed: bool) -> str:
    if category in {"admin", "internal", "debug"}:
        return "potential sensitive route referenced; requires manual verification"
    if category in {"graphql", "websocket"}:
        return "interactive endpoint referenced or observed"
    if category in {"staging", "dev", "test"}:
        return "non-production route naming referenced"
    if category in {"auth", "upload", "download"}:
        return "authentication or file-flow route should be manually reviewed"
    if _is_high_interest(value, category):
        return "high-interest keyword present"
    if observed:
        return "observed browser route"
    return "recovered route; requires manual verification"


def _reason_for_js_route(value: str, matched_pattern: str, source_type: str) -> str:
    category = _category_for(value, source_type)
    if matched_pattern in {"fetch", "axios", "axios.request", "XMLHttpRequest.open"}:
        return "network call pattern references this route"
    if matched_pattern in {"router.push", "navigate", "history.pushState", "window.location", "window.open"}:
        return "client-side navigation pattern references this route"
    if category in {"admin", "internal", "debug", "graphql", "websocket"}:
        return f"{category} route keyword recovered from JavaScript"
    return "route-like JavaScript string recovered after noise filtering"


def _observed_url_set(devtools: dict[str, Any]) -> set[str]:
    output: set[str] = set()
    for request in devtools.get("network_requests") or []:
        if isinstance(request, dict):
            key = _route_key(str(request.get("url") or ""))
            if key:
                output.add(key)
    for key_name in ("dom_links", "loaded_js", "loaded_css", "websocket_urls"):
        for value in devtools.get(key_name) or []:
            key = _route_key(str(value or ""))
            if key:
                output.add(key)
    return output


def _is_high_interest(value: str, category: str) -> bool:
    lowered = f"{value} {category}".lower()
    return category in {"admin", "graphql", "websocket", "debug", "internal", "staging", "dev", "test", "metrics", "health"} or any(keyword in lowered for keyword in HIGH_INTEREST_KEYWORDS)


def _dynamic_import_high_interest(row: dict[str, Any]) -> bool:
    lowered = f"{row.get('import_path') or ''} {row.get('resolved_url') or ''} {row.get('chunk_name') or ''}".lower()
    return any(keyword in lowered for keyword in DYNAMIC_IMPORT_KEYWORDS)


def _interest_score(value: str, category: str, observed: bool) -> int:
    score = 10
    if observed:
        score += 15
    if category in {"admin", "internal", "debug"}:
        score += 55
    elif category in {"graphql", "websocket", "auth"}:
        score += 45
    elif category in {"api", "upload", "download", "metrics", "health"}:
        score += 30
    elif category in {"staging", "dev", "test", "docs"}:
        score += 24
    if _is_high_interest(value, category):
        score += 12
    if _is_static_application_asset(value):
        score -= 20
    return score


def _is_static_application_asset(value: str) -> bool:
    raw = str(value or "").lower()
    parsed = urlparse(raw)
    path = parsed.path or raw
    return any(path.endswith(extension) for extension in STATIC_ROUTE_EXTENSIONS) or is_static_asset(raw)


def _is_noise_route(value: str) -> bool:
    raw = str(value or "").strip()
    if not raw or len(raw) < 2 or len(raw) > 900:
        return True
    lowered = raw.lower()
    if any(part in lowered for part in NOISE_PATH_PARTS):
        return True
    if re.fullmatch(r"/?[a-f0-9]{16,}(?:\.[a-z0-9]+)?", lowered):
        return True
    if re.fullmatch(r"[A-Za-z0-9+/=_-]{40,}", raw):
        return True
    if "sourceMappingURL=data:" in raw:
        return True
    return is_noise_url(raw) and not _is_static_application_asset(raw)


def _looks_like_route_candidate(value: str) -> bool:
    raw = str(value or "").strip()
    if not raw or _is_noise_route(raw):
        return False
    if _is_static_application_asset(raw):
        return False
    if raw.startswith(("http://", "https://", "ws://", "wss://")):
        return True
    if "${" in raw:
        raw = re.sub(r"\$\{[^}]+\}", ":param", raw)
    if raw.startswith(("#/", "/", "./", "../")) and ROUTE_STRING_RE.match(raw.lstrip("#")):
        return True
    lowered = raw.lower()
    if any(keyword in lowered for keyword in HIGH_INTEREST_KEYWORDS) and "/" in raw:
        return True
    return False


def _clean_js_literal(value: str) -> str:
    raw = str(value or "").strip().strip("\"'`")
    raw = raw.replace("\\/", "/")
    raw = re.sub(r"\\u([0-9a-fA-F]{4})", lambda match: chr(int(match.group(1), 16)), raw)
    raw = re.sub(r"\\x([0-9a-fA-F]{2})", lambda match: chr(int(match.group(1), 16)), raw)
    raw = re.sub(r"\$\{[^}]+\}", ":param", raw)
    return unquote(raw)


def _decode_js_text(text: str) -> str:
    value = str(text or "").replace("\\/", "/")
    value = re.sub(r"\\u([0-9a-fA-F]{4})", lambda match: chr(int(match.group(1), 16)), value)
    value = re.sub(r"\\x([0-9a-fA-F]{2})", lambda match: chr(int(match.group(1), 16)), value)
    for _ in range(2):
        updated = re.sub(
            r"""(["'`])([^"'`\\]{1,180})\1\s*\+\s*(["'`])([^"'`\\]{1,180})\3""",
            lambda match: f'"{match.group(2)}{match.group(4)}"',
            value,
        )
        if updated == value:
            break
        value = updated
    return value


def _inline_script_text(html_text: str) -> str:
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_text, "html.parser")
        return "\n".join(
            str(tag.string or tag.get_text("\n", strip=False) or "")
            for tag in soup.find_all("script")
            if not tag.get("src")
        )
    except Exception:
        return "\n".join(match.group(1) for match in re.finditer(r"<script(?![^>]+\bsrc=)[^>]*>(.*?)</script>", html_text, re.I | re.S))


def _framework_hint(text: str) -> str:
    lowered = str(text or "").lower()
    for name, markers in FRAMEWORK_HINTS:
        if any(marker.lower() in lowered for marker in markers):
            return name
    return ""


def _chunk_name(value: str, context: str) -> str:
    raw = str(value or "")
    match = re.search(r"webpackChunkName\s*:\s*['\"]([^'\"]+)['\"]", context or "")
    if match:
        return match.group(1)
    path = urlparse(raw).path if "://" in raw else raw
    name = path.rsplit("/", 1)[-1].split("?", 1)[0]
    return name or raw[:80]


def _method_from_context(context: str) -> str:
    match = METHOD_FROM_CONTEXT_RE.search(context or "")
    return match.group(1).upper() if match else ""


def _context(text: str, start: int, end: int) -> str:
    return _compact(str(text or "")[max(0, start - 90) : min(len(text or ""), end + 140)])


def _compact(value: str, limit: int = MAX_CONTEXT) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def _tag_context(tag: Any) -> str:
    try:
        return _compact(str(tag), 240)
    except Exception:
        return ""


def _join_unique(left: str, right: str) -> str:
    return ", ".join(_list_unique([item.strip() for item in f"{left},{right}".split(",") if item.strip()]))[:240]


def _list_unique(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        clean = str(value or "").strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        output.append(clean)
    return output


def _max_confidence(left: str, right: str) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    left = (left or "low").lower()
    right = (right or "low").lower()
    return left if order.get(left, 0) >= order.get(right, 0) else right


def _stronger_risk(left: str, right: str) -> str:
    if not left:
        return right
    if not right:
        return left
    order = ("manual verification", "sensitive", "interactive", "non-production", "authentication", "high-interest", "observed", "recovered")
    left_score = next((index for index, marker in enumerate(order) if marker in left.lower()), len(order))
    right_score = next((index for index, marker in enumerate(order) if marker in right.lower()), len(order))
    return left if left_score <= right_score else right
