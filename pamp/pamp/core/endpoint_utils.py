from __future__ import annotations

import re
from urllib.parse import unquote, urljoin, urlparse, urlunparse


STATIC_EXTENSIONS = {
    ".css",
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
}
ENDPOINT_SEGMENTS = {
    "api",
    "rest",
    "graphql",
    "gql",
    "auth",
    "oauth",
    "oauth2",
    "oidc",
    "login",
    "logout",
    "signin",
    "signout",
    "session",
    "sessions",
    "user",
    "users",
    "profile",
    "admin",
    "internal",
    "debug",
    "callback",
    "webhook",
    "payment",
    "checkout",
    "upload",
    "download",
    "token",
    "authorize",
    "openid",
}
CODE_MARKERS = ("function", "return", "=>", ");", "{", "}", "webpack", "__proto__")


def is_static_asset(value: str) -> bool:
    raw = str(value or "").strip()
    if not raw:
        return False
    parsed = urlparse(raw)
    path = parsed.path.lower()
    if any(path.endswith(extension) for extension in STATIC_EXTENSIONS):
        return True
    return bool(
        re.search(
            r"(?:^|/)(?:_next|static|assets?|chunks?|fonts?|images?|img|css)/.*\.(?:js|css|map|png|jpe?g|gif|svg|webp|woff2?)$",
            path,
            re.I,
        )
    )


def is_noise_url(value: str) -> bool:
    raw = str(value or "").strip()
    if not raw or len(raw) > 180 or any(char.isspace() for char in raw):
        return True
    lowered = raw.lower()
    if lowered.startswith(("data:", "blob:", "javascript:")):
        return True
    if any(marker in lowered for marker in CODE_MARKERS):
        return True
    if any(char in raw for char in "{}()$"):
        return True
    if raw.count("%") > 10 or raw.count("\\x") > 4 or raw.count("\\u") > 4:
        return True
    if sum(not (char.isalnum() or char in "/:._?&=%#@+~-[]") for char in raw) > 8:
        return True
    if re.search(r"[A-Za-z_$][\w$]*\([^)]{15,}\)", raw):
        return True
    if re.search(r"(?:^|[?&])(?:code|value|data)=.{80,}", raw, re.I):
        return True
    return is_static_asset(raw)


def normalize_endpoint(value: str, base_url: str = "") -> str:
    raw = str(value or "").strip().strip("\"'`")
    if not raw:
        return ""
    raw = unquote(raw)
    raw = raw.replace("\\/", "/").replace("&amp;", "&")
    if raw.startswith("//"):
        scheme = urlparse(base_url).scheme or "https"
        raw = f"{scheme}:{raw}"
    elif raw.startswith(("/", "./", "../")) and base_url:
        raw = urljoin(base_url, raw)
    elif not raw.startswith(("http://", "https://", "ws://", "wss://")):
        if raw.startswith(("api/", "v1/", "v2/", "auth/", "oauth/", "graphql")) and base_url:
            raw = urljoin(base_url.rstrip("/") + "/", raw)
        else:
            return ""
    try:
        parsed = urlparse(raw)
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https", "ws", "wss"} or not parsed.netloc:
        return ""
    cleaned = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))
    return cleaned if not is_noise_url(cleaned) else ""


def is_probable_endpoint(value: str) -> bool:
    raw = str(value or "").strip()
    if is_noise_url(raw):
        return False
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https", "ws", "wss"} or not parsed.netloc:
        return False
    if parsed.scheme in {"ws", "wss"}:
        return True
    host = (parsed.hostname or "").lower()
    if host.startswith("api.") or ".api." in host:
        return True
    segments = [unquote(segment).lower() for segment in parsed.path.split("/") if segment]
    if any(
        segment in ENDPOINT_SEGMENTS
        or segment in {"api-docs", "swagger-ui"}
        or re.fullmatch(r"v\d+", segment)
        for segment in segments
    ):
        return True
    query_keys = {key.lower() for key in re.findall(r"(?:^|[?&])([^=&]+)=", raw)}
    return bool(query_keys & {"client_id", "redirect_uri", "scope", "response_type", "operationname"})
