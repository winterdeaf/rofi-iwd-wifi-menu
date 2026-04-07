"""Text helpers for safe rofi and markup output."""

from __future__ import annotations

import html


_CONTROL_REPLACEMENTS = {
    ord("\0"): " ",
    ord("\r"): " ",
    ord("\n"): " ",
    ord("\x1f"): " ",
    127: " ",
}


def sanitize_rofi(value: object) -> str:
    text = "" if value is None else str(value)
    text = text.translate(_CONTROL_REPLACEMENTS)
    return "".join(ch if ord(ch) >= 32 else " " for ch in text)


def escape_markup(value: object) -> str:
    return html.escape(sanitize_rofi(value), quote=False)
