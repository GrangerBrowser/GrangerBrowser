from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_LANGUAGE = "en"
SUPPORTED_LANGUAGES = {"ru", "en"}


def normalize_language(value: str | None) -> str:
    raw = str(value or DEFAULT_LANGUAGE).strip().lower()
    if raw in {"eng", "english"}:
        raw = "en"
    if raw in {"rus", "russian"}:
        raw = "ru"
    return raw if raw in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE


def load_locale(language: str | None = None) -> dict[str, str]:
    lang = normalize_language(language)
    locales_dir = Path(__file__).resolve().parent / "locales"
    fallback = json.loads((locales_dir / f"{DEFAULT_LANGUAGE}.json").read_text(encoding="utf-8"))
    payload = fallback
    if lang != DEFAULT_LANGUAGE:
        localized = json.loads((locales_dir / f"{lang}.json").read_text(encoding="utf-8"))
        payload = {**fallback, **localized}
    return {str(key): str(value) for key, value in payload.items()}


def load_all_locales() -> dict[str, dict[str, str]]:
    return {lang: load_locale(lang) for lang in sorted(SUPPORTED_LANGUAGES)}


def translate(locale: dict[str, str], key: str, default: Any = "") -> str:
    return locale.get(key, str(default if default != "" else key))
