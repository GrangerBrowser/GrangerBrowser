from __future__ import annotations

import re


STATIC_EXTENSIONS = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".woff",
    ".woff2",
)
CONFIG_NAMES = (
    ".env",
    "config",
    "settings",
    "web.config",
    "appsettings",
    "application.yml",
    "application.yaml",
)


def classify_path(path: str, category_hint: str = "", content_type: str = "") -> str:
    lowered = str(path or "").lower()
    hint = str(category_hint or "").lower()
    if lowered.endswith(".map"):
        return "sourcemap"
    if any(name in lowered for name in CONFIG_NAMES):
        return "config"
    if "graphql" in lowered:
        return "graphql"
    if any(item in lowered for item in ("swagger", "openapi")):
        return "swagger"
    if hint in {"admin", "auth", "api", "backup", "config", "docs", "sourcemap", "graphql", "swagger"}:
        return hint
    if any(item in lowered for item in ("auth", "oauth", "sso", "signin", "sign-in", "login")):
        return "auth"
    if any(item in lowered for item in ("admin", "panel", "dashboard", "wp-admin")):
        return "admin"
    if any(item in lowered for item in ("api", "rest", "v1/", "v2/", "webhook", "callback")) or re.search(r"\bapi\d*\b", lowered):
        return "api"
    if any(item in lowered for item in ("docs", "redoc", "api-docs")):
        return "docs"
    if any(item in lowered for item in ("backup", "dump", ".bak", ".old", ".sql", ".zip", ".tar", "archive")):
        return "backup"
    if lowered in {"robots.txt", "sitemap.xml", "security.txt", "ads.txt", "humans.txt", "manifest.json", "manifest.webmanifest"}:
        return "public"
    if lowered.endswith(STATIC_EXTENSIONS) or "javascript" in str(content_type).lower():
        return "static"
    return "unknown"
