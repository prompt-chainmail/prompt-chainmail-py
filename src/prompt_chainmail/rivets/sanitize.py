from __future__ import annotations

import re

from prompt_chainmail.rivets.base import FnRivet, NextFn, Rivet
from prompt_chainmail.rivets.types import SecurityFlags, ThreatLevel
from prompt_chainmail.rivets.utils import apply_threat_penalty
from prompt_chainmail.shared.regex_patterns import COMMON_PATTERNS, HTML_ENTITIES
from prompt_chainmail.types import ChainmailContext, ChainmailResult

_HTML_TAG = re.compile(r"<[^>]*>")
_CONTROL_CHAR = re.compile(r"[\x7F]")
_CONTROL_CHAR_REPLACEMENT = "[CTRL_REDACTED]"
_DEFAULT_MAX_LENGTH = 8000


def sanitize(max_length: int | None = None) -> Rivet:
    limit = _DEFAULT_MAX_LENGTH if max_length is None else max_length

    def handler(context: ChainmailContext, nxt: NextFn) -> ChainmailResult:
        sanitized = context.sanitized
        original_length = len(sanitized)

        sanitized_html = sanitized
        while _HTML_TAG.search(sanitized_html):
            sanitized_html = _HTML_TAG.sub("", sanitized_html)
        if sanitized_html != sanitized:
            context.flags.add(SecurityFlags.SANITIZED_HTML_TAGS)
            sanitized = sanitized_html

        sanitized = HTML_ENTITIES.amp.sub("&", sanitized)
        sanitized = HTML_ENTITIES.lt.sub("<", sanitized)
        sanitized = HTML_ENTITIES.gt.sub(">", sanitized)
        sanitized = HTML_ENTITIES.quot.sub('"', sanitized)
        sanitized = HTML_ENTITIES.apos.sub("'", sanitized)

        controls_removed = sanitized
        while _CONTROL_CHAR.search(controls_removed):
            controls_removed = _CONTROL_CHAR.sub(_CONTROL_CHAR_REPLACEMENT, controls_removed)
        if controls_removed != sanitized:
            context.flags.add(SecurityFlags.SANITIZED_CONTROL_CHARS)
            sanitized = controls_removed

        before_whitespace = sanitized
        normalized = sanitized
        while True:
            match = COMMON_PATTERNS.whitespace_multiple.search(normalized)
            if match is not None and len(match.group(0)) > 1:
                normalized = COMMON_PATTERNS.whitespace_multiple.sub(" ", normalized, count=1)
            else:
                break
        sanitized = normalized.strip()

        if sanitized != before_whitespace:
            context.flags.add(SecurityFlags.SANITIZED_WHITESPACE)

        if len(sanitized) > limit:
            sanitized = sanitized[:limit]

        if len(sanitized) < original_length:
            if len(sanitized) < len(context.input):
                context.flags.add(SecurityFlags.SANITIZED_CONTROL_CHARS)
            sanitization_ratio = (original_length - len(sanitized)) / original_length
            if sanitization_ratio > 0.1:
                apply_threat_penalty(context, ThreatLevel.MEDIUM)
            else:
                apply_threat_penalty(context, ThreatLevel.LOW)

        if len(sanitized) < len(context.input):
            context.flags.add(SecurityFlags.TRUNCATED)

        context.sanitized = sanitized
        return nxt(context)

    return FnRivet("sanitize", handler)
