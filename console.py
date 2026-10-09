#!/usr/bin/env python3
"""
PyFireSOC - Console output helpers

The alert and report output uses emoji. A legacy Windows console runs on cp1252
and raises UnicodeEncodeError on them, which killed the packet callback the
moment the first alert fired. Everything printed by the app goes through
safe_print(), which degrades to ASCII instead of raising.
"""

import sys

# ASCII stand-ins for the glyphs used in alerts and reports
_FALLBACKS = {
    "\U0001f6a8": "[!]",   # rotating light
    "\U0001f4c5": "[date]",
    "\U0001f4cc": "[title]",
    "\U0001f4dd": "[desc]",
    "\U0001f310": "[src]",
    "\U0001f4ca": "[stats]",
    "\U0001f4cb": "[list]",
    "\U0001f514": "[alert]",
    "\U0001f3af": "[top]",
    "⚔️": "[attacks]",
    "⚔": "[attacks]",
    "\U0001f525": "[high]",
    "⚠️": "[warn]",
    "⚠": "[warn]",
    "ℹ️": "[info]",
    "ℹ": "[info]",
}


def to_ascii(text: str) -> str:
    """Replace known glyphs, then drop anything else non-encodable"""
    for glyph, plain in _FALLBACKS.items():
        text = text.replace(glyph, plain)
    return text.encode("ascii", "replace").decode("ascii")


def safe_print(*args, **kwargs):
    """print() that survives a console which cannot encode the output"""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        print(*[to_ascii(str(a)) for a in args], **kwargs)


def enable_utf8_stdout():
    """Switch stdout/stderr to UTF-8 where the runtime allows it.

    Called once at start-up; on a console that cannot do it, safe_print()
    still keeps the output readable.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
