from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlparse


def run_crawler_agent(domain_data: dict[str, Any] | None = None) -> dict[str, Any]:
    domain_data = domain_data or {}
    html = domain_data.get("html") or {}
    links = list(html.get("external_links") or [])
    links.extend(html.get("login_admin_paths") or [])
    links.extend(html.get("api_endpoint_candidates") or [])
    forms = list(html.get("forms") or [])
    parameterized_urls = [url for url in links if parse_qsl(urlparse(str(url)).query, keep_blank_values=True)]
    return {
        "agent": {"name": "crawler_agent", "role": "links, forms and page parameters"},
        "links": _unique_strings(links, 350),
        "forms": forms[:120],
        "parameterized_urls": _unique_strings(parameterized_urls, 220),
        "summary": {
            "links": len(_unique_strings(links, 350)),
            "forms": len(forms[:120]),
            "parameterized_urls": len(_unique_strings(parameterized_urls, 220)),
        },
    }


def _unique_strings(values: list[Any], limit: int) -> list[str]:
    output = []
    seen = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
        if len(output) >= limit:
            break
    return output
