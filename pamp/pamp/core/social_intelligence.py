from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests

from .data_decoder import sanitize_url


REQUEST_TIMEOUT = 8
USER_AGENT = "Pamp/1.0 (+public-metadata; no-auth)"
PROFILE_LIMIT = 24
RECENT_POST_LIMIT = 5
HTML_LIMIT = 650_000

PLATFORM_HOSTS = {
    "X": ("x.com", "twitter.com"),
    "Facebook": ("facebook.com",),
    "Instagram": ("instagram.com",),
    "YouTube": ("youtube.com", "youtu.be"),
    "TikTok": ("tiktok.com",),
    "Telegram": ("t.me", "telegram.me"),
    "Discord": ("discord.gg", "discord.com"),
    "Reddit": ("reddit.com",),
    "GitHub": ("github.com",),
    "LinkedIn": ("linkedin.com",),
    "Pinterest": ("pinterest.com", "pin.it"),
    "Medium": ("medium.com",),
    "Spotify": ("spotify.com", "open.spotify.com"),
    "Steam": ("steamcommunity.com", "store.steampowered.com"),
    "Twitch": ("twitch.tv",),
    "VK": ("vk.com",),
    "OK": ("ok.ru",),
    "WhatsApp": ("wa.me",),
}

PROFILE_NOISE_PATHS = {
    "X": ("intent", "share", "search", "home", "i/flow"),
    "Facebook": ("sharer", "share.php", "dialog"),
    "LinkedIn": ("sharing", "sharearticle"),
    "Pinterest": ("pin/create",),
    "Telegram": ("share",),
    "Reddit": ("submit",),
    "WhatsApp": ("send",),
    "YouTube": ("watch", "shorts", "playlist"),
    "Spotify": ("track", "album", "episode"),
}

COUNT_PATTERNS = {
    "followers": (
        r"([\d.,]+\s*[KMBkmb]?)\s+(?:followers|subscribers)",
        r'"followersCount"\s*:\s*"?([\d.,]+[KMBkmb]?)"?',
        r'"followerCount"\s*:\s*"?([\d.,]+[KMBkmb]?)"?',
        r'"edge_followed_by"\s*:\s*\{\s*"count"\s*:\s*(\d+)',
        r'"follower_count"\s*:\s*(\d+)',
    ),
    "following": (
        r"([\d.,]+\s*[KMBkmb]?)\s+(?:following)",
        r'"followingCount"\s*:\s*"?([\d.,]+[KMBkmb]?)"?',
        r'"edge_follow"\s*:\s*\{\s*"count"\s*:\s*(\d+)',
        r'"following_count"\s*:\s*(\d+)',
    ),
    "posts": (
        r"([\d.,]+\s*[KMBkmb]?)\s+(?:posts|videos|repos|public_repos)",
        r'"postsCount"\s*:\s*"?([\d.,]+[KMBkmb]?)"?',
        r'"videoCount"\s*:\s*"?([\d.,]+[KMBkmb]?)"?',
        r'"edge_owner_to_timeline_media"\s*:\s*\{\s*"count"\s*:\s*(\d+)',
        r'"public_repos"\s*:\s*(\d+)',
    ),
}


def collect_social_profiles(
    links: list[str],
    errors: list[str] | None = None,
    execution_log: list[dict[str, str]] | None = None,
    link_sources: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    profiles: list[dict[str, Any]] = []
    seen: set[str] = set()
    for link in links[:120]:
        url = normalize_social_url(str(link or "").strip())
        platform = social_platform(url)
        if not url or url in seen or not is_social_profile_candidate(url, platform):
            continue
        seen.add(url)
        source = (link_sources or {}).get(str(link)) or (link_sources or {}).get(url) or "HTML social_links"
        profiles.append(profile_from_public_url(url, errors, discovery_source=source))
        if len(profiles) >= PROFILE_LIMIT:
            break
    if execution_log is not None:
        warnings = sum(1 for row in profiles if row.get("fetch_status") not in {"ok", "link_only"})
        execution_log.append(
            {
                "stage": "social_metadata",
                "status": f"completed ({len(profiles)} profile(s), {warnings} warning(s))",
            }
        )
    return profiles


def profile_from_public_url(
    url: str,
    errors: list[str] | None = None,
    discovery_source: str = "HTML social_links",
) -> dict[str, Any]:
    platform = social_platform(url)
    handle = social_handle(url, platform)
    profile = _empty_profile(url, platform, handle, discovery_source)
    if platform == "GitHub" and handle:
        return _github_profile(profile, handle, errors)
    return _html_profile(profile, errors)


def build_social_intelligence(
    profiles: list[dict[str, Any]],
    target_domain: str,
) -> dict[str, Any]:
    target_host = _host(target_domain)
    normalized_profiles: list[dict[str, Any]] = []
    handle_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    external_domain_groups: dict[str, list[str]] = defaultdict(list)
    errors: list[str] = []

    for source in profiles:
        if not isinstance(source, dict):
            continue
        profile = dict(source)
        profile["normalized_url"] = profile.get("normalized_url") or normalize_social_url(profile.get("url") or "")
        external_links = _dedupe_urls(profile.get("external_links") or profile.get("website_links") or [])
        profile["external_links"] = external_links
        profile["website_links"] = profile.get("website_links") or external_links
        links_back = any(_same_or_subdomain(_host(link), target_host) for link in external_links if target_host)
        profile["links_back_to_target"] = links_back
        profile["official_likelihood"] = "high" if links_back else "medium"
        normalized_profiles.append(profile)

        handle_key = _handle_key(profile.get("handle") or profile.get("username") or "")
        if handle_key:
            handle_groups[handle_key].append(profile)
        for link in external_links:
            host = _host(link)
            if host and not _is_social_host(host):
                external_domain_groups[host].append(str(profile.get("platform") or "Other social"))
        if profile.get("error"):
            errors.append(f"{profile.get('platform')}: {profile.get('error')}")

    reused_handles = [
        {
            "handle": handle,
            "platforms": sorted({str(row.get("platform") or "Other social") for row in rows}),
            "profiles": [str(row.get("url") or "") for row in rows],
        }
        for handle, rows in sorted(handle_groups.items())
        if len({str(row.get("platform") or "") for row in rows}) > 1
    ]
    shared_domains = [
        {"domain": domain, "platforms": sorted(set(platforms))}
        for domain, platforms in sorted(external_domain_groups.items())
        if len(set(platforms)) > 1
    ]
    brand_name = _identity_name(normalized_profiles, target_domain)
    identity_map = {
        "name": brand_name,
        "profiles": [
            {
                "platform": row.get("platform"),
                "handle": row.get("handle") or row.get("display_name"),
                "url": row.get("url"),
                "verified": row.get("verified"),
                "confidence": row.get("confidence"),
                "official_likelihood": row.get("official_likelihood"),
            }
            for row in normalized_profiles
        ],
        "reused_handles": reused_handles,
        "shared_external_domains": shared_domains,
    }

    signals = _social_signals(normalized_profiles, reused_handles, target_host)
    recent_posts = sum(len(row.get("recent_posts") or []) for row in normalized_profiles)
    external_links = {
        link
        for row in normalized_profiles
        for link in (row.get("external_links") or [])
        if link
    }
    warning_statuses = {"blocked", "login_required", "unavailable", "rate_limited", "fetch_failed"}
    summary = {
        "platforms_found": len({row.get("platform") for row in normalized_profiles if row.get("platform")}),
        "profiles_analyzed": len(normalized_profiles),
        "verified_profiles": sum(1 for row in normalized_profiles if row.get("verified") is True),
        "recent_posts_found": recent_posts,
        "external_links_found": len(external_links),
        "reused_handles": len(reused_handles),
        "fetch_warnings": sum(1 for row in normalized_profiles if row.get("fetch_status") in warning_statuses),
    }
    return {
        "summary": summary,
        "profiles": normalized_profiles,
        "identity_map": identity_map,
        "signals": signals,
        "errors": errors[:40],
    }


def normalize_social_url(value: str) -> str:
    clean = sanitize_url(str(value or "").strip())
    if not clean:
        return ""
    parsed = urlparse(clean)
    host = (parsed.hostname or "").lower().removeprefix("www.")
    if not host:
        return ""
    if host == "twitter.com":
        host = "x.com"
    query = [
        (key, item)
        for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        if not key.lower().startswith("utm_") and key.lower() not in {"fbclid", "gclid", "ref_src"}
    ]
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    if path != "/":
        path = path.rstrip("/")
    return urlunparse(("https", host, path, "", urlencode(query), ""))


def is_social_profile_candidate(url: str, platform: str) -> bool:
    if not url or platform == "Other social":
        return False
    path = (urlparse(url).path or "").strip("/").lower()
    if not path:
        return False
    return not any(path == item or path.startswith(f"{item}/") for item in PROFILE_NOISE_PATHS.get(platform, ()))


def _empty_profile(url: str, platform: str, handle: str, discovery_source: str) -> dict[str, Any]:
    normalized = normalize_social_url(url)
    return {
        "platform": platform,
        "url": url,
        "normalized_url": normalized,
        "href": url,
        "handle": handle,
        "username": handle.lstrip("@") if handle else None,
        "display_name": handle or None,
        "title": None,
        "description": None,
        "bio": None,
        "avatar": None,
        "avatar_url": None,
        "banner": None,
        "banner_url": None,
        "followers": None,
        "followers_count": None,
        "following": None,
        "following_count": None,
        "posts": None,
        "posts_count": None,
        "verified": None,
        "profile_type": "public profile",
        "profile_category": None,
        "external_links": [],
        "website_links": [],
        "location": None,
        "joined_date": None,
        "account_created_at": None,
        "last_public_activity": None,
        "language": None,
        "public_email": None,
        "public_phone": None,
        "recent_posts": [],
        "redirect_chain": [],
        "evidence": [f"Profile URL was found in {discovery_source}."],
        "sources": [discovery_source],
        "raw_metadata": {},
        "confidence": "medium",
        "source": discovery_source,
        "fetch_status": "pending",
        "error": None,
    }


def _github_profile(profile: dict[str, Any], handle: str, errors: list[str] | None) -> dict[str, Any]:
    username = handle.strip("@").split("/", 1)[0]
    profile["username"] = username
    try:
        response = requests.get(
            f"https://api.github.com/users/{username}",
            headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        status = _fetch_status(response.status_code)
        profile["fetch_status"] = status
        if response.status_code >= 400:
            profile["error"] = f"HTTP {response.status_code}"
            return profile
        data = response.json()
        blog = sanitize_url(str(data.get("blog") or "").strip())
        if blog and not blog.startswith(("http://", "https://")):
            blog = f"https://{blog}"
        recent_posts = _github_recent_events(username)
        created = data.get("created_at")
        updated = data.get("updated_at")
        profile.update(
            {
                "url": sanitize_url(data.get("html_url") or response.url) or profile["url"],
                "normalized_url": normalize_social_url(data.get("html_url") or response.url),
                "display_name": data.get("name") or username,
                "title": data.get("name") or username,
                "description": data.get("bio"),
                "bio": data.get("bio"),
                "avatar": data.get("avatar_url"),
                "avatar_url": data.get("avatar_url"),
                "followers": data.get("followers"),
                "followers_count": data.get("followers"),
                "following": data.get("following"),
                "following_count": data.get("following"),
                "posts": data.get("public_repos"),
                "posts_count": data.get("public_repos"),
                "profile_type": data.get("type") or "User",
                "profile_category": data.get("type") or "User",
                "external_links": [blog] if blog else [],
                "website_links": [blog] if blog else [],
                "location": data.get("location"),
                "joined_date": created,
                "account_created_at": created,
                "last_public_activity": updated,
                "public_email": data.get("email"),
                "recent_posts": recent_posts,
                "evidence": profile["evidence"] + ["Public GitHub profile metadata returned by an unauthenticated endpoint."],
                "sources": profile["sources"] + ["public GitHub API"],
                "raw_metadata": {
                    "company": data.get("company"),
                    "hireable": data.get("hireable"),
                    "public_gists": data.get("public_gists"),
                },
                "confidence": "high",
                "source": "public GitHub API",
                "fetch_status": "ok",
                "error": None,
            }
        )
    except Exception as exc:  # noqa: BLE001 - metadata failure must not fail the scan
        _record_fetch_error(profile, exc, errors)
    return profile


def _github_recent_events(username: str) -> list[dict[str, Any]]:
    try:
        response = requests.get(
            f"https://api.github.com/users/{username}/events/public?per_page={RECENT_POST_LIMIT}",
            headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code != 200:
            return []
        rows = response.json()
        output = []
        for row in rows[:RECENT_POST_LIMIT] if isinstance(rows, list) else []:
            repo = str((row.get("repo") or {}).get("name") or "")
            output.append(
                {
                    "title": f"{row.get('type') or 'Public event'}: {repo}".strip(": "),
                    "text_preview": repo,
                    "date": row.get("created_at"),
                    "url": f"https://github.com/{repo}" if repo else f"https://github.com/{username}",
                    "media_type": "activity",
                    "engagement": {},
                    "links": [f"https://github.com/{repo}"] if repo else [],
                    "hashtags": [],
                    "mentions": [],
                    "source": "public GitHub events",
                    "confidence": "high",
                }
            )
        return output
    except Exception:  # noqa: BLE001 - optional recent activity is best effort
        return []


def _html_profile(profile: dict[str, Any], errors: list[str] | None) -> dict[str, Any]:
    try:
        response = requests.get(
            profile["url"],
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        profile["fetch_status"] = _fetch_status(response.status_code)
        profile["redirect_chain"] = _redirect_chain(response)
        if response.status_code >= 400:
            profile["error"] = f"HTTP {response.status_code}"
            return profile
        html = response.text[:HTML_LIMIT]
        if not html:
            profile["fetch_status"] = "fetch_failed"
            profile["error"] = "Empty response"
            return profile

        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, "html.parser")
        json_data = _embedded_json(soup)
        og_title = _meta(soup, "og:title")
        twitter_title = _meta(soup, "twitter:title")
        html_title = soup.title.string.strip() if soup.title and soup.title.string else ""
        title = _first(og_title, twitter_title, html_title)
        og_description = _meta(soup, "og:description")
        twitter_description = _meta(soup, "twitter:description")
        description = _first(og_description, twitter_description, _meta(soup, "description"))
        avatar = _first(
            _meta(soup, "og:image"),
            _meta(soup, "twitter:image"),
            _meta(soup, "twitter:image:src"),
            _json_find_url(json_data, ("avatar", "avatarUrl", "avatar_url", "image", "imageUrl")),
            _link_href(soup, "apple-touch-icon", profile["url"]),
            _link_href(soup, "icon", profile["url"]),
        )
        banner = _first(
            _json_find_url(json_data, ("banner", "bannerUrl", "banner_url", "profileBannerUrl", "cover")),
            _meta(soup, "og:image:secure_url"),
        )
        external_links = _external_links(response.url, soup, json_data)
        public_email, public_phone = _public_contacts(soup, json_data)
        followers = _count_value("followers", html, json_data)
        following = _count_value("following", html, json_data)
        posts = _count_value("posts", html, json_data)
        created = _json_find_scalar(json_data, ("created_at", "createdAt", "dateCreated", "joinedDate"))
        last_activity = _json_find_scalar(
            json_data,
            ("updated_at", "updatedAt", "lastActivity", "lastPublishedAt", "dateModified"),
        )
        category = _first(_meta(soup, "og:type"), str(_json_find_scalar(json_data, ("profileType", "category", "@type")) or ""))
        language = _first(
            str((soup.html or {}).get("lang") or "") if soup.html else "",
            _meta(soup, "og:locale"),
            str(_json_find_scalar(json_data, ("inLanguage", "language")) or ""),
        )
        final_url = sanitize_url(response.url) or profile["url"]
        sources = list(profile["sources"])
        if soup.find("meta", attrs={"property": re.compile(r"^og:", re.I)}):
            sources.append("OpenGraph")
        if soup.find("meta", attrs={"name": re.compile(r"^twitter:", re.I)}):
            sources.append("Twitter Cards")
        if json_data:
            sources.append("JSON-LD / embedded JSON")
        sources.append("profile page fetch")
        if profile["redirect_chain"]:
            sources.append("redirect chain")
        evidence = list(profile["evidence"])
        if title:
            evidence.append("Public title metadata found.")
        if description:
            evidence.append("Public profile description found.")
        if avatar:
            evidence.append("Public profile image metadata found.")
        clean_title = _clean_title(title, profile["platform"], profile["handle"])
        access_status = _page_access_status(html, title, description, avatar, profile["platform"])
        rich_metadata = bool(description or avatar or (title and not _is_generic_title(title, profile["platform"])))
        profile.update(
            {
                "url": final_url,
                "normalized_url": normalize_social_url(final_url),
                "display_name": clean_title,
                "title": clean_title,
                "description": _clean_description(description),
                "bio": _clean_description(description),
                "avatar": _absolute(final_url, avatar) if avatar else None,
                "avatar_url": _absolute(final_url, avatar) if avatar else None,
                "banner": _absolute(final_url, banner) if banner and banner != avatar else None,
                "banner_url": _absolute(final_url, banner) if banner and banner != avatar else None,
                "followers": followers,
                "followers_count": followers,
                "following": following,
                "following_count": following,
                "posts": posts,
                "posts_count": posts,
                "verified": _verified_hint(html, json_data, profile["handle"]),
                "profile_type": _profile_type(profile["platform"], html, json_data),
                "profile_category": category or None,
                "external_links": external_links,
                "website_links": external_links,
                "location": _json_find_scalar(json_data, ("location", "addressLocality")),
                "joined_date": created,
                "account_created_at": created,
                "last_public_activity": last_activity,
                "language": language or None,
                "public_email": public_email,
                "public_phone": public_phone,
                "recent_posts": _recent_posts(json_data, final_url),
                "evidence": _unique_strings(evidence, 12),
                "sources": _unique_strings(sources, 12),
                "raw_metadata": _compact_mapping(
                    {
                        "og_title": og_title,
                        "twitter_title": twitter_title,
                        "og_type": _meta(soup, "og:type"),
                        "locale": _meta(soup, "og:locale"),
                        "canonical": _link_href(soup, "canonical", final_url),
                    }
                ),
                "confidence": "high" if rich_metadata else profile["confidence"],
                "source": " + ".join(_unique_strings(sources, 4)),
                "fetch_status": access_status,
                "error": None,
            }
        )
    except Exception as exc:  # noqa: BLE001 - metadata failure must not fail the scan
        _record_fetch_error(profile, exc, errors)
    return profile


def social_platform(url: str) -> str:
    host = _host(url)
    for platform, hosts in PLATFORM_HOSTS.items():
        if any(host == item or host.endswith(f".{item}") for item in hosts):
            return platform
    return "Other social"


def social_handle(url: str, platform: str) -> str:
    parsed = urlparse(url)
    parts = [part for part in parsed.path.split("/") if part]
    query = dict(parse_qsl(parsed.query))
    if platform == "Facebook" and query.get("id"):
        return query["id"]
    if not parts:
        return parsed.hostname or ""
    if platform in {"Telegram", "Instagram", "X", "TikTok", "Twitch", "Medium"}:
        return f"@{parts[0].lstrip('@')}"
    if platform == "LinkedIn" and parts[0] in {"in", "company", "school"}:
        return "/".join(parts[:2])
    if platform == "YouTube":
        return parts[0] if parts[0].startswith("@") else "/".join(parts[:2])
    if platform == "Discord":
        return parts[-1]
    if platform == "Spotify" and len(parts) > 1:
        return "/".join(parts[:2])
    if platform == "Steam" and len(parts) > 1:
        return "/".join(parts[:2])
    return parts[0]


def _fetch_status(status_code: int) -> str:
    if status_code in {401, 407}:
        return "login_required"
    if status_code == 403:
        return "blocked"
    if status_code in {404, 410}:
        return "unavailable"
    if status_code == 429:
        return "rate_limited"
    if status_code >= 400:
        return "fetch_failed"
    return "ok"


def _page_access_status(html: str, title: str, description: str, avatar: str, platform: str) -> str:
    lowered = html[:250_000].lower()
    challenge_markers = ("cf-chl-", "captcha", "checking your browser", "access denied")
    login_markers = ("log in to continue", "login required", "sign in to view", "you must be logged in")
    if any(marker in lowered for marker in challenge_markers) and not (title or description or avatar):
        return "blocked"
    if any(marker in lowered for marker in login_markers):
        return "login_required"
    if _is_generic_title(title, platform) and not (description or avatar) and platform in {"Facebook", "Instagram", "TikTok"}:
        return "login_required"
    return "ok"


def _redirect_chain(response: Any) -> list[dict[str, Any]]:
    history = list(getattr(response, "history", []) or [])
    rows = []
    for index, item in enumerate(history):
        next_url = history[index + 1].url if index + 1 < len(history) else getattr(response, "url", "")
        rows.append({"from": str(item.url), "to": str(next_url), "status": item.status_code})
    return rows[:8]


def _recent_posts(blocks: list[Any], base_url: str) -> list[dict[str, Any]]:
    allowed_types = {"socialmediaposting", "blogposting", "article", "newsarticle", "videoobject", "posting"}
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in _json_dicts(blocks):
        item_type = str(row.get("@type") or row.get("type") or "").lower()
        if item_type not in allowed_types:
            continue
        title = _first(
            str(row.get("headline") or ""),
            str(row.get("name") or ""),
            str(row.get("title") or ""),
        )
        preview = _clean_description(str(row.get("text") or row.get("description") or row.get("caption") or "")) or ""
        date = row.get("datePublished") or row.get("uploadDate") or row.get("created_at") or row.get("publishedAt")
        url = _absolute(base_url, str(row.get("url") or row.get("mainEntityOfPage") or ""))
        dedupe_key = url or f"{date}:{title}:{preview[:80]}"
        if not dedupe_key.strip(":") or dedupe_key in seen or not (date or url):
            continue
        seen.add(dedupe_key)
        text_value = " ".join(part for part in (title, preview) if part)
        links = re.findall(r"https?://[^\s\"'<>]+", text_value)
        output.append(
            {
                "title": title[:180] or None,
                "text_preview": preview[:320] or None,
                "date": date,
                "url": url or None,
                "media_type": item_type,
                "engagement": _compact_mapping(
                    {
                        "likes": row.get("likeCount") or row.get("likes"),
                        "comments": row.get("commentCount") or row.get("comments"),
                        "shares": row.get("shareCount") or row.get("shares"),
                        "views": row.get("viewCount") or row.get("views"),
                    }
                ),
                "links": _dedupe_urls(links)[:8],
                "hashtags": sorted(set(re.findall(r"(?<!\w)#[\w-]+", text_value, re.UNICODE)))[:12],
                "mentions": sorted(set(re.findall(r"(?<!\w)@[\w.-]+", text_value, re.UNICODE)))[:12],
                "source": "public embedded metadata",
                "confidence": "medium",
            }
        )
        if len(output) >= RECENT_POST_LIMIT:
            break
    return output


def _social_signals(
    profiles: list[dict[str, Any]],
    reused_handles: list[dict[str, Any]],
    target_host: str,
) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    likely_official = [row for row in profiles if row.get("official_likelihood") in {"high", "medium"}]
    verified = [row for row in profiles if row.get("verified") is True]
    backlinks = [row for row in profiles if row.get("links_back_to_target")]
    recent = [row for row in profiles if row.get("recent_posts") or row.get("last_public_activity")]
    invites = [row for row in profiles if row.get("platform") == "Discord" or "invite" in str(row.get("profile_type") or "").lower()]
    created = [row for row in profiles if row.get("account_created_at") or row.get("joined_date")]
    emails = [row for row in profiles if row.get("public_email")]
    phones = [row for row in profiles if row.get("public_phone")]
    warnings = [
        row
        for row in profiles
        if row.get("fetch_status") in {"blocked", "login_required", "unavailable", "rate_limited", "fetch_failed"}
    ]
    if likely_official:
        signals.append(_signal("Official social profile detected", len(likely_official), "medium", "Profiles are linked from the target website."))
    if verified:
        signals.append(_signal("Verified account detected", len(verified), "high", ", ".join(str(row.get("platform")) for row in verified)))
    for row in reused_handles:
        signals.append(_signal("Multiple platforms share the same handle", row.get("handle"), "high", ", ".join(row.get("platforms") or [])))
    if backlinks:
        signals.append(_signal("Profile links back to target domain", len(backlinks), "high", target_host))
    if recent:
        signals.append(_signal("Recent public activity detected", len(recent), "medium", "Activity metadata is publicly visible."))
    if invites:
        signals.append(_signal("Invite link detected", len(invites), "high", ", ".join(str(row.get("url")) for row in invites[:3])))
    if emails:
        signals.append(_signal("Public email exposed", len(emails), "high", "Explicit public profile metadata."))
    if phones:
        signals.append(_signal("Public phone exposed", len(phones), "high", "Explicit public profile metadata."))
    if created:
        signals.append(_signal("Account creation date available", len(created), "high", "Public account metadata."))
    for row in warnings:
        name = "Profile requires login to inspect" if row.get("fetch_status") == "login_required" else "Social account could not be verified"
        signals.append(_signal(name, row.get("platform"), "medium", f"{row.get('fetch_status')}: {row.get('url')}", risk="warn"))
    return signals[:40]


def _signal(
    name: str,
    value: Any,
    confidence: str,
    evidence: str,
    risk: str = "info",
) -> dict[str, Any]:
    return {
        "name": name,
        "type": "osint_signal",
        "value": value,
        "source": "social_intelligence",
        "confidence": confidence,
        "evidence": evidence,
        "risk": risk,
        "notes": "OSINT context signal; not a security vulnerability.",
    }


def _identity_name(profiles: list[dict[str, Any]], target_domain: str) -> str:
    names = [
        re.sub(r"\s+", " ", str(row.get("display_name") or "")).strip()
        for row in profiles
        if str(row.get("display_name") or "").strip()
    ]
    useful = [name for name in names if not name.startswith("@") and len(name) > 2]
    return Counter(useful).most_common(1)[0][0] if useful else target_domain


def _handle_key(value: Any) -> str:
    handle = str(value or "").strip().lower().lstrip("@").strip("/")
    if not handle or handle in {"profile.php", "channel", "user", "company", "home"}:
        return ""
    if "/" in handle and handle.split("/", 1)[0] in {"channel", "user", "company", "artist"}:
        handle = handle.split("/", 1)[1]
    return handle if len(handle) >= 3 else ""


def _meta(soup: Any, key: str) -> str:
    pattern = re.compile(f"^{re.escape(key)}$", re.I)
    tag = (
        soup.find("meta", attrs={"property": pattern})
        or soup.find("meta", attrs={"name": pattern})
        or soup.find("meta", attrs={"itemprop": pattern})
    )
    return str(tag.get("content") or "").strip() if tag else ""


def _link_href(soup: Any, rel: str, base_url: str) -> str:
    tag = soup.find(
        "link",
        rel=lambda value: value and rel.lower() in " ".join(value if isinstance(value, list) else [value]).lower(),
    )
    return _absolute(base_url, tag.get("href")) if tag and tag.get("href") else ""


def _embedded_json(soup: Any) -> list[Any]:
    blocks: list[Any] = []
    for tag in soup.find_all("script")[:120]:
        script_type = str(tag.get("type") or "").lower()
        script_id = str(tag.get("id") or "").lower()
        raw = (tag.string or tag.get_text() or "").strip()
        if not raw or len(raw) > 2_500_000:
            continue
        if "json" in script_type or script_id in {"__next_data__", "sigi_state"}:
            try:
                blocks.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
        if len(blocks) >= 16:
            break
    return blocks


def _json_walk(value: Any) -> Any:
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _json_walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _json_walk(item)


def _json_dicts(values: list[Any]) -> Any:
    for value in values:
        if isinstance(value, dict):
            yield value
            for item in value.values():
                yield from _json_dicts([item])
        elif isinstance(value, list):
            for item in value:
                yield from _json_dicts([item])


def _json_find_scalar(blocks: list[Any], keys: tuple[str, ...]) -> Any:
    keyset = {key.lower() for key in keys}
    for key, value in _json_items(blocks):
        if key.lower() in keyset and isinstance(value, (str, int, float, bool)):
            return value
    return None


def _json_find_url(blocks: list[Any], keys: tuple[str, ...]) -> str:
    value = _json_find_scalar(blocks, keys)
    return str(value or "") if value else ""


def _json_items(blocks: list[Any]) -> list[tuple[str, Any]]:
    output: list[tuple[str, Any]] = []
    for block in blocks:
        output.extend(list(_json_walk(block)))
        if len(output) >= 6000:
            break
    return output[:6000]


def _count_value(kind: str, html: str, blocks: list[Any]) -> Any:
    json_keys = {
        "followers": ("followers", "followersCount", "followerCount", "subscriberCount"),
        "following": ("following", "followingCount", "friendsCount"),
        "posts": ("posts", "postsCount", "public_repos", "videoCount", "awemeCount"),
    }
    scalar = _json_find_scalar(blocks, json_keys[kind])
    if scalar not in (None, ""):
        return scalar
    for pattern in COUNT_PATTERNS[kind]:
        match = re.search(pattern, html, re.I)
        if match:
            return match.group(1).strip()
    return None


def _verified_hint(html: str, blocks: list[Any], handle: str) -> bool | None:
    target = _handle_key(handle)
    for row in _json_dicts(blocks):
        username = _handle_key(
            row.get("username")
            or row.get("screen_name")
            or row.get("screenName")
            or row.get("uniqueId")
            or row.get("handle")
            or ""
        )
        if not target or username != target:
            continue
        for key in ("verified", "isVerified", "is_verified"):
            if isinstance(row.get(key), bool):
                return row[key]
    lowered = html[:250_000].lower()
    if "verified account" in lowered:
        return True
    return None


def _profile_type(platform: str, html: str, blocks: list[Any]) -> str:
    scalar = _json_find_scalar(blocks, ("profileType", "accountType"))
    if scalar:
        return str(scalar)[:80]
    if platform == "LinkedIn":
        return "public profile metadata"
    if platform == "Telegram" and "members" in html.lower():
        return "public channel or group"
    if platform == "Discord":
        return "public invite"
    return "public profile"


def _external_links(base_url: str, soup: Any, blocks: list[Any]) -> list[str]:
    links: list[str] = []
    for key, value in _json_items(blocks):
        if key.lower() in {"url", "sameas", "externalurl", "website", "blog"}:
            if isinstance(value, str):
                links.append(value)
            elif isinstance(value, list):
                links.extend(str(item) for item in value if isinstance(item, str))
    for tag in soup.find_all("a", href=True)[:120]:
        href = _absolute(base_url, tag.get("href"))
        if href and not _same_or_subdomain(_host(href), _host(base_url)) and _host(href) not in {"t.co", "l.instagram.com", "l.facebook.com"}:
            links.append(href)
    base_host = _host(base_url)
    return [
        link
        for link in _dedupe_urls(links)
        if not _same_or_subdomain(_host(link), base_host)
        and _host(link) not in {"t.co", "l.instagram.com", "l.facebook.com"}
    ][:12]


def _public_contacts(soup: Any, blocks: list[Any]) -> tuple[str | None, str | None]:
    email = None
    phone = None
    mail = soup.find("a", href=re.compile(r"^mailto:", re.I))
    tel = soup.find("a", href=re.compile(r"^tel:", re.I))
    if mail:
        email = str(mail.get("href") or "").split(":", 1)[-1].split("?", 1)[0].strip() or None
    if tel:
        phone = str(tel.get("href") or "").split(":", 1)[-1].strip() or None
    email = email or _json_find_scalar(blocks, ("email", "contactEmail"))
    phone = phone or _json_find_scalar(blocks, ("telephone", "phone", "phoneNumber"))
    return (str(email)[:180] if email else None, str(phone)[:80] if phone else None)


def _clean_title(title: str, platform: str, handle: str) -> str | None:
    text = re.sub(r"\s+", " ", str(title or "")).strip()
    if not text:
        return handle or None
    if _is_generic_title(text, platform):
        return handle or platform
    for suffix in (f" | {platform}", f" - {platform}", f" on {platform}", " | Instagram", " | Facebook", " / X"):
        if text.endswith(suffix):
            text = text[: -len(suffix)].strip()
    if " (@" in text:
        text = text.split(" (@", 1)[0].strip()
    return text[:180] or handle or None


def _is_generic_title(title: str, platform: str) -> bool:
    normalized = re.sub(r"\s+", " ", str(title or "")).strip().lower()
    generic = {
        "Facebook": {"facebook", "log into facebook", "facebook - log in or sign up"},
        "Instagram": {"instagram", "instagram login"},
        "TikTok": {"tiktok", "tiktok - make your day", "make your day"},
        "X": {"x", "x. it's what's happening / x"},
    }
    return normalized in generic.get(platform, set())


def _clean_description(description: str) -> str | None:
    text = re.sub(r"\s+", " ", str(description or "")).strip()
    return text[:500] if text else None


def _first(*values: str) -> str:
    for value in values:
        if value:
            return str(value)
    return ""


def _absolute(base_url: str, value: str | None) -> str:
    if not value:
        return ""
    return sanitize_url(urljoin(base_url, str(value).strip()))


def _dedupe_urls(values: list[Any]) -> list[str]:
    output = []
    seen = set()
    for value in values:
        clean = sanitize_url(str(value or "").strip())
        if not clean or not clean.startswith(("http://", "https://")) or clean in seen:
            continue
        seen.add(clean)
        output.append(clean)
    return output


def _compact_mapping(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}


def _unique_strings(values: list[Any], limit: int) -> list[str]:
    output = []
    seen = set()
    for value in values:
        item = str(value or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        output.append(item)
        if len(output) >= limit:
            break
    return output


def _record_fetch_error(profile: dict[str, Any], exc: Exception, errors: list[str] | None) -> None:
    profile["fetch_status"] = "fetch_failed"
    profile["error"] = str(exc)
    if errors is not None:
        errors.append(f"social metadata {profile['url']}: {exc}")


def _host(url: str) -> str:
    value = str(url or "").strip()
    if "://" not in value:
        value = f"https://{value}"
    return (urlparse(value).hostname or "").lower().removeprefix("www.")


def _is_social_host(host: str) -> bool:
    return any(host == item or host.endswith(f".{item}") for hosts in PLATFORM_HOSTS.values() for item in hosts)


def _same_or_subdomain(host: str, target: str) -> bool:
    return bool(host and target and (host == target or host.endswith(f".{target}") or target.endswith(f".{host}")))


def _parse_date(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None
