from __future__ import annotations

from prompt_chainmail.rivets.base import FnRivet, NextFn, Rivet
from prompt_chainmail.rivets.types import SecurityFlags, ThreatLevel
from prompt_chainmail.rivets.utils import apply_threat_penalty
from prompt_chainmail.shared.regex_patterns import COMMON_PATTERNS
from prompt_chainmail.types import ChainmailContext, ChainmailResult

_EXCESSIVE_LINES_THRESHOLD = 50
_NON_ASCII_THRESHOLD = 0.3
_WORD_THRESHOLD = 10
_UNIQUE_WORDS_THRESHOLD = 0.3


def structure_analysis() -> Rivet:
    def handler(context: ChainmailContext, nxt: NextFn) -> ChainmailResult:
        lines = context.sanitized.split("\n")
        if len(lines) > _EXCESSIVE_LINES_THRESHOLD:
            context.flags.add(SecurityFlags.EXCESSIVE_LINES)
            apply_threat_penalty(context, ThreatLevel.LOW)

        char_len = len(context.sanitized)
        non_ascii = sum(1 for ch in context.sanitized if not (0x20 <= ord(ch) <= 0x7E))
        if char_len > 0 and non_ascii / char_len > _NON_ASCII_THRESHOLD:
            context.flags.add(SecurityFlags.NON_ASCII_HEAVY)
            apply_threat_penalty(context, ThreatLevel.LOW)

        words = COMMON_PATTERNS.whitespace_multiple.split(context.sanitized.lower())
        unique_words = set(words)
        if (
            len(words) > _WORD_THRESHOLD
            and len(unique_words) / len(words) < _UNIQUE_WORDS_THRESHOLD
        ):
            context.flags.add(SecurityFlags.REPETITIVE_CONTENT)
            apply_threat_penalty(context, ThreatLevel.LOW)

        return nxt(context)

    return FnRivet("structure_analysis", handler)
