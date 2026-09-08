from __future__ import annotations

import re
from functools import lru_cache

from prompt_chainmail.rivets.base import FnRivet, NextFn, Rivet
from prompt_chainmail.rivets.types import SecurityFlags, ThreatLevel
from prompt_chainmail.rivets.utils import apply_threat_penalty
from prompt_chainmail.types import ChainmailContext, ChainmailResult

_PATTERN_SOURCES: tuple[tuple[str, str], ...] = (
    (
        r"(?i)\b(you\s+are|act\s+as|behave\s+like)\s+(a\s+)?(admin|administrator|system|root|developer|expert|master)\b",
        "role_confusion",
    ),
    (
        r"(?i)\b(you\s+are\s+now|now\s+you\s+are)\s+(a\s+)?(helpful\s+)?(assistant|ai|bot|system)\s+(that|who)\s+(ignores?|disregards?|bypasses?)\b",
        "assistant_redefinition",
    ),
    (
        r"(?i)\b(ignore|forget|disregard|override)\s+(all\s+)?(previous\s+)?(instructions?|rules?|prompts?|safety\s+guidelines?)\b",
        "instruction_override",
    ),
    (r"(?i)\b(act\s+as\s+dan|as\s+dan|do\s+anything\s+now)\b", "dan_jailbreak"),
    (r"(?i)\b(forget\s+everything\s+above\s+and\s+act)\b", "forget_and_act"),
    (
        r"(?i)\b(switch\s+to|change\s+to|enter)\s+(developer|debug|admin|test)\s+mode\b",
        "mode_switching",
    ),
    (r"(?i)\b(system|admin)\s*:\s*(ignore|override|reset|disable)\b", "system_command"),
    (
        r"(?i)\b(jailbreak|break\s+out|escape\s+from)\s+(the\s+)?(system|constraints?)\b",
        "jailbreak",
    ),
)


@lru_cache(maxsize=1)
def injection_patterns() -> list[tuple[re.Pattern[str], str]]:
    return [(re.compile(pat), label) for pat, label in _PATTERN_SOURCES]


def pattern_detection(custom_patterns: list[re.Pattern[str]] | None = None) -> Rivet:
    extras = custom_patterns or []

    def handler(context: ChainmailContext, nxt: NextFn) -> ChainmailResult:
        for pattern, label in injection_patterns():
            if pattern.search(context.sanitized):
                context.flags.add(SecurityFlags.INJECTION_PATTERN)
                apply_threat_penalty(context, ThreatLevel.HIGH)
                context.metadata["matched_pattern"] = label
                return nxt(context)

        for pattern in extras:
            if pattern.search(context.sanitized):
                context.flags.add(SecurityFlags.INJECTION_PATTERN)
                apply_threat_penalty(context, ThreatLevel.HIGH)
                context.metadata["matched_pattern"] = pattern.pattern
                break

        return nxt(context)

    return FnRivet("pattern_detection", handler)
