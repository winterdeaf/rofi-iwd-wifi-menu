"""Helpers for encoding rofi action payloads safely."""

from __future__ import annotations

import base64
import json
from typing import Any

ACTION_PREFIX = "iwdrofimenu:"


def _b64encode(raw: str) -> str:
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def _b64decode(raw: str) -> str:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode((raw + padding).encode("ascii")).decode("utf-8")


def encode_action(action: str, **payload: Any) -> str:
    data = {"action": action, **payload}
    raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    return ACTION_PREFIX + _b64encode(raw)


def decode_action(raw: str | None) -> dict[str, Any] | None:
    if not raw or not raw.startswith(ACTION_PREFIX):
        return None
    try:
        data = json.loads(_b64decode(raw[len(ACTION_PREFIX):]))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or "action" not in data:
        return None
    return data
