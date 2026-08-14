from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

import requests

from .endpoint_utils import is_static_asset
from .intelligence_common import (
    DebugLog,
    compact_text,
    dedupe_findings,
    finding,
    mask_secret,
    record_error,
)


TIMEOUT = 8
USER_AGENT = "Pamp/Domain-Analyzer"
URL_PATTERN = re.compile(r"""https?://[^\s"'`<>\\]{5,300}|/(?:api/auth|oauth2?|oidc|openid|auth|login|signin|callback|authorize|token)(?:/[A-Za-z0-9_.~:@!$&'()*+,;=%-]*)*(?:\?[^\s"'`<>\\]{0,180})?""", re.I)
CLIENT_ID_PATTERN = re.compile(r"""(?i)\bclient[_-]?id\b\s*[:=]\s*["'`]([^"'`]{3,240})["'`]""")
SCOPE_PATTERN = re.compile(r"""(?i)\bscope\b\s*[:=]\s*["'`]([^"'`]{2,300})["'`]""")
TOKEN_PATTERN = re.compile(r"""(?i)\b(client_secret|access_token|refresh_token|id_token)\b\s*[:=]\s*["'`]([^"'`]{8,500})["'`]""")
PROVIDERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Google", ("accounts.google.com", "google oauth", "google-signin")),
    ("Microsoft", ("login.microsoftonline.com", "microsoft oauth", "azuread")),
    ("GitHub", ("github.com/login/oauth", "github oauth")),
    ("Discord", ("discord.com/oauth2", "discord oauth")),
    ("Telegram", ("oauth.telegram.org", "telegram login", "telegram-login", "telegramloginwidget")),
    ("Steam", ("steamcommunity.com/openid", "openid/login", "steam auth", "/auth/steam")),
    ("VK", ("oauth.vk.com", "vk oauth")),
    ("Apple", ("appleid.apple.com", "sign in with apple")),
    ("Facebook", ("facebook.com/dialog/oauth", "facebook login")),
    ("Twitter/X", ("twitter.com/i/oauth2", "x.com/i/oauth2")),
    ("Yandex", ("oauth.yandex.", "yandex oauth")),
    ("Auth0", ("auth0.com", "createauth0client")),
    ("Keycloak", ("keycloak", "/protocol/openid-connect/")),
    ("Okta", ("okta.com/oauth", "oktaauth")),
    ("Clerk", ("clerk.com", "__clerk")),
    ("NextAuth", ("next-auth", "/api/auth/session", "/api/auth/providers")),
    ("Supabase Auth", ("supabase.auth", "supabase.co/auth/v1")),
    ("Firebase Auth", ("firebaseauth", "identitytoolkit.googleapis.com")),
)
AUTH_ROUTE_MARKERS = (
    "/api/auth",
    "/api/auth/session",
    "/api/auth/signin",
    "/api/auth/callback",
    "/api/auth/providers",
    "/oauth",
    "/oauth2",
    "/authorize",
    "/token",
    "/openid",
    "/login",
    "/signin",
    "/callback",
)


def analyze_oauth(
    base_url: str,
    sources: list[dict[str, Any]],
    debug_log: DebugLog | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    providers = []
    auth_routes = []
    callbacks = []
    client_ids = []
    scopes = []
    oidc_metadata = []
    sessions = []
    well_known_urls = {
        urljoin(base_url, "/.well-known/openid-configuration"),
        urljoin(base_url, "/.well-known/oauth-authorization-server"),
    } if base_url else set()

    for source_row in sources:
        source = str(source_row.get("source") or "domain analysis")
        for structured in _iter_dicts(source_row.get("value")):
            item_type = str(structured.get("type") or "").lower()
            item_name = str(structured.get("name") or "")
            item_value = str(structured.get("value") or "")
            if item_type == "oauth_client_id" and item_value:
                client_ids.append(_client_id_finding(item_value, source, structured.get("source") or "JavaScript Intelligence"))
            if item_type == "third_party_sdk" and item_name in {provider for provider, _ in PROVIDERS}:
                providers.append(
                    finding(
                        name=item_name,
                        item_type="oauth_provider",
                        value=item_name,
                        source=source,
                        confidence=str(structured.get("confidence") or "medium"),
                        evidence=str(structured.get("evidence") or f"{item_name} SDK marker"),
                        risk="low",
                        notes="Provider SDK marker; no authentication attempt was made.",
                        provider=item_name,
                    )
                )
        for text in _source_values(source_row.get("value")):
            lowered = text.lower()
            for provider, markers in PROVIDERS:
                marker = next((item for item in markers if item in lowered), "")
                if marker:
                    providers.append(
                        finding(
                            name=provider,
                            item_type="oauth_provider",
                            value=provider,
                            source=source,
                            confidence="high" if "://" in marker or "/" in marker else "medium",
                            evidence=f"Provider marker found: {marker}",
                            risk="low",
                            notes="Provider detection only; no authentication attempt was made.",
                            provider=provider,
                        )
                    )
            if re.search(r"""https?://t\.me/[A-Za-z0-9_/-]*bot(?:[/?\s"'`]|$)""", text, re.I):
                providers.append(
                    finding(
                        name="Telegram",
                        item_type="oauth_provider",
                        value="Telegram",
                        source=source,
                        confidence="medium",
                        evidence="Telegram bot or login-widget URL found",
                        risk="low",
                        notes="Provider marker only; no login interaction was performed.",
                        provider="Telegram",
                    )
                )
            for raw in URL_PATTERN.findall(text):
                value = _normalize_route(raw, base_url)
                if not value:
                    continue
                parsed = urlparse(value)
                query = parse_qs(parsed.query)
                path = parsed.path.lower()
                if not _is_auth_url(value, query):
                    continue
                if "/.well-known/" in path:
                    well_known_urls.add(value)
                route_type = _route_type(path)
                risk = "medium" if route_type in {"callback", "token", "authorize"} else "low"
                route = finding(
                    name=route_type.replace("_", " ").title(),
                    item_type=route_type,
                    value=value,
                    source=source,
                    confidence="high" if value.startswith(("http://", "https://")) else "medium",
                    evidence=f"Authentication route marker found in {source}",
                    risk=risk,
                    notes="Passive route discovery; endpoint was not used for login.",
                    provider=_provider_for_text(value),
                    route=value,
                )
                auth_routes.append(route)
                route_provider = str(route.get("provider") or "")
                if route_provider:
                    providers.append(
                        finding(
                            name=route_provider,
                            item_type="oauth_provider",
                            value=route_provider,
                            source=source,
                            confidence="high",
                            evidence=f"Provider-specific auth route found: {value}",
                            risk="low",
                            notes="Provider route detection only; no authentication attempt was made.",
                            provider=route_provider,
                        )
                    )
                if route_type == "callback" or "redirect_uri" in query:
                    callback_value = query.get("redirect_uri", [value])[0]
                    callbacks.append(
                        finding(
                            name="OAuth callback",
                            item_type="callback_url",
                            value=callback_value,
                            source=source,
                            confidence="high",
                            evidence=f"Callback or redirect_uri found in {value}",
                            risk="medium",
                            notes="Callback exposure is normal but should be validated against provider allowlists.",
                            provider=route["provider"],
                            route=value,
                        )
                    )
                for value_id in query.get("client_id", []):
                    client_ids.append(_client_id_finding(value_id, source, value))
                for scope_value in query.get("scope", []):
                    scopes.append(_scope_finding(scope_value, source, value))
            for match in CLIENT_ID_PATTERN.finditer(text):
                client_ids.append(_client_id_finding(match.group(1), source, "JavaScript/config assignment"))
            for match in SCOPE_PATTERN.finditer(text):
                scopes.append(_scope_finding(match.group(1), source, "JavaScript/config assignment"))
            for match in TOKEN_PATTERN.finditer(text):
                token_type, token_value = match.groups()
                sessions.append(
                    finding(
                        name=token_type,
                        item_type="secret_like_auth_value",
                        value=mask_secret(token_value),
                        source=source,
                        confidence="high",
                        evidence=f"{token_type} assignment found; value masked",
                        risk="high",
                        notes="Masked authentication material; review the original source securely.",
                        provider=_provider_for_text(text),
                    )
                )
            for marker in ("localStorage", "sessionStorage", "session_state", "id_token", "access_token", "refresh_token"):
                if marker.lower() in lowered:
                    sessions.append(
                        finding(
                            name=marker,
                            item_type="session_indicator",
                            value=marker,
                            source=source,
                            confidence="medium",
                            evidence=f"Session marker {marker} found",
                            risk="medium" if "token" in marker.lower() else "low",
                            notes="Indicator only; storage contents were not modified.",
                            provider=_provider_for_text(text),
                        )
                    )

    for url in sorted(well_known_urls)[:8]:
        metadata = _fetch_metadata(url, debug_log, errors)
        if not metadata:
            continue
        oidc_metadata.append(
            finding(
                name="OIDC metadata",
                item_type="oidc_metadata",
                value=url,
                source="safe well-known GET",
                confidence="high",
                evidence=f"HTTP 200 metadata issuer={metadata.get('issuer') or 'unknown'}",
                risk="low",
                notes="Public discovery metadata only; no authorization request was sent.",
                provider=_provider_for_text(str(metadata)),
                issuer=str(metadata.get("issuer") or ""),
                authorization_endpoint=str(metadata.get("authorization_endpoint") or ""),
                token_endpoint=str(metadata.get("token_endpoint") or ""),
                scopes_supported=metadata.get("scopes_supported") or [],
            )
        )
        authorization_endpoint = str(metadata.get("authorization_endpoint") or "")
        if authorization_endpoint:
            auth_routes.append(
                finding(
                    name="Authorization endpoint",
                    item_type="authorize",
                    value=authorization_endpoint,
                    source=url,
                    confidence="high",
                    evidence="OIDC discovery authorization_endpoint",
                    risk="low",
                    notes="Metadata reference; endpoint was not invoked.",
                    provider=_provider_for_text(authorization_endpoint),
                    route=authorization_endpoint,
                )
            )

    providers = dedupe_findings(providers, ("name", "value"), 60)
    auth_routes = dedupe_findings(auth_routes, ("type", "value"), 240)
    callbacks = dedupe_findings(callbacks, ("value", "source"), 120)
    client_ids = dedupe_findings(client_ids, ("value", "source"), 120)
    scopes = dedupe_findings(scopes, ("value", "source"), 120)
    oidc_metadata = dedupe_findings(oidc_metadata, ("value",), 20)
    sessions = dedupe_findings(sessions, ("type", "value", "source"), 160)
    return {
        "providers": providers,
        "auth_routes": auth_routes,
        "callback_urls": callbacks,
        "client_ids": client_ids,
        "scopes": scopes,
        "oidc_metadata": oidc_metadata,
        "session_indicators": sessions,
        "summary": {
            "providers": len(providers),
            "auth_routes": len(auth_routes),
            "callback_urls": len(callbacks),
            "client_ids": len(client_ids),
            "scopes": len(scopes),
            "oidc_metadata": len(oidc_metadata),
            "session_indicators": len(sessions),
            "high_risk": sum(1 for row in sessions if row.get("risk") == "high"),
        },
        "errors": errors,
    }


def _source_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value[:2_000_000]]
    if isinstance(value, dict):
        return [str(item) for item in value.values() if item is not None][:800]
    if isinstance(value, (list, tuple, set)):
        rows = []
        for item in value:
            if isinstance(item, dict):
                rows.append(" ".join(str(value) for value in item.values() if value is not None))
            elif item is not None:
                rows.append(str(item))
            if len(rows) >= 1500:
                break
        return rows
    return [str(value)] if value is not None else []


def _iter_dicts(value: Any) -> list[dict[str, Any]]:
    rows = []
    queue = [value]
    while queue and len(rows) < 2000:
        current = queue.pop()
        if isinstance(current, dict):
            rows.append(current)
            queue.extend(current.values())
        elif isinstance(current, (list, tuple, set)):
            queue.extend(current)
    return rows


def _normalize_route(value: str, base_url: str) -> str:
    raw = value.strip().replace("\\/", "/").rstrip(".,;:)]}'\"`$")
    if raw.startswith(("http://", "https://")):
        return raw[:300]
    if raw.startswith("/") and base_url:
        return urljoin(base_url, raw)[:300]
    return ""


def _route_type(path: str) -> str:
    if "callback" in path:
        return "callback"
    if "authorize" in path:
        return "authorize"
    if path.endswith("/token") or "/token/" in path:
        return "token"
    if "session" in path:
        return "session"
    if "provider" in path:
        return "providers"
    if "signin" in path or "login" in path:
        return "login"
    if "openid" in path or "oidc" in path:
        return "oidc"
    return "auth_route"


def _is_auth_url(value: str, query: dict[str, list[str]]) -> bool:
    if is_static_asset(value):
        return False
    lowered = value.lower()
    path = urlparse(value).path.lower()
    if "/.well-known/" in path:
        return True
    if any(marker in path for marker in AUTH_ROUTE_MARKERS):
        return True
    if set(query) & {
        "client_id",
        "redirect_uri",
        "scope",
        "response_type",
        "code_challenge",
        "code_challenge_method",
        "state",
    }:
        return True
    provider_url_markers = (
        "accounts.google.com/o/oauth",
        "login.microsoftonline.com",
        "github.com/login/oauth",
        "discord.com/oauth2",
        "oauth.telegram.org",
        "steamcommunity.com/openid",
        "oauth.vk.com",
        "appleid.apple.com",
        "facebook.com/dialog/oauth",
        "twitter.com/i/oauth2",
        "x.com/i/oauth2",
        "oauth.yandex.",
        "/protocol/openid-connect/",
        "supabase.co/auth/v1",
        "identitytoolkit.googleapis.com",
    )
    return any(marker in lowered for marker in provider_url_markers)


def _provider_for_text(value: str) -> str:
    lowered = value.lower()
    for provider, markers in PROVIDERS:
        if any(marker in lowered for marker in markers):
            return provider
    return ""


def _client_id_finding(value: str, source: str, evidence_source: str) -> dict[str, Any]:
    clean = compact_text(value, 240)
    return finding(
        name="OAuth client_id",
        item_type="client_id",
        value=clean,
        source=source,
        confidence="high",
        evidence=f"client_id found in {compact_text(evidence_source, 160)}",
        risk="medium",
        notes="Client IDs are commonly public, but should be correlated with strict callback allowlists.",
        provider=_provider_for_text(evidence_source),
    )


def _scope_finding(value: str, source: str, evidence_source: str) -> dict[str, Any]:
    clean = compact_text(value, 300)
    wide = any(item in clean.lower().split() for item in {"admin", "offline_access", "*"})
    return finding(
        name="OAuth scope",
        item_type="scope",
        value=clean,
        source=source,
        confidence="high",
        evidence=f"scope found in {compact_text(evidence_source, 160)}",
        risk="medium" if wide else "low",
        notes="Wide scopes deserve manual review." if wide else "Observed authorization scope.",
        provider=_provider_for_text(evidence_source),
    )


def _fetch_metadata(
    url: str,
    debug_log: DebugLog | None,
    errors: list[str],
) -> dict[str, Any]:
    try:
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=TIMEOUT,
            allow_redirects=True,
        )
        if response.status_code != 200:
            return {}
        payload = response.json()
        return payload if isinstance(payload, dict) else {}
    except Exception as exc:
        record_error(errors, debug_log, "[DOMAIN][OAUTH]", f"url={url} error={exc}")
        return {}
