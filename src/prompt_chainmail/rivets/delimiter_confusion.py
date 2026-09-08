from __future__ import annotations

import re
from functools import lru_cache

from prompt_chainmail.rivets.base import FnRivet, NextFn, Rivet
from prompt_chainmail.rivets.types import SecurityFlags, ThreatLevel
from prompt_chainmail.rivets.utils import apply_threat_penalty
from prompt_chainmail.types import ChainmailContext, ChainmailResult

_SOURCES = (
    r""""{3,}|'{3,}""",
    r"`{3,}",
    r"(?i)</(?:prompt|system|instruction|assistant|user|human|ai|bot)>",
    r"(?i)</(?:example|demo|test|input|output|response)>",
    r"(?i)\[(?:END|STOP|DONE|EXIT|QUIT)\]",
    r"(?i)(?:---|\*\*\*|===)(?:END|STOP|DONE)(?:---|\*\*\*|===)",
    r"\{{3,}|\}{3,}",
    r"\[\[\[|\]\]\]",
    r"\$\${2,}|#{3,}",
    r"!{3,}|\?{3,}",
    r"(?i)\[/(?:INST|SYS)\]|\[(?:INST|SYS)\]",
    r"(?i)<\|(?:endoftext|im_end|im_start|end_of_turn)\|>",
    r"(?i)<(?:start|end)_of_turn>",
    r"```[\s\S]*?```",
    r"~~~[\s\S]*?~~~",
    r"<!--[\s\S]*?-->",
    r"/\*[\s\S]*?\*/",
    r"(?m)//.*$",
    r"(?i)<(?:system|instruction|prompt)>[\s\S]*?</(?:system|instruction|prompt)>",
    r"(?i)\[(?:SYSTEM|INSTRUCTION|PROMPT)\][\s\S]*?\[/(?:SYSTEM|INSTRUCTION|PROMPT)\]",
    r"(?i)<(?:user|human|assistant|ai|bot)>[\s\S]*?</(?:user|human|assistant|ai|bot)>",
    r"(?i)\[(?:USER|HUMAN|ASSISTANT|AI|BOT)\][\s\S]*?\[/(?:USER|HUMAN|ASSISTANT|AI|BOT)\]",
    r"[-=_]{10,}",
    r"\*{5,}",
    r"\\n\\n\\n+",
    r"\\[trn]{3,}",
    r"(?:%[0-9A-Fa-f]{2}){5,}",
    r"(?:&#x?[0-9A-Fa-f]+;){3,}",
    r"[\x01-\x1F\x7F]{2,}",
    r"[\u2000-\u200F\u202A-\u202E]",
)


@lru_cache(maxsize=1)
def _patterns() -> list[re.Pattern[str]]:
    return [re.compile(src) for src in _SOURCES]


def delimiter_confusion() -> Rivet:
    def handler(context: ChainmailContext, nxt: NextFn) -> ChainmailResult:
        for pattern in _patterns():
            if pattern.search(context.sanitized):
                context.flags.add(SecurityFlags.DELIMITER_CONFUSION)
                apply_threat_penalty(context, ThreatLevel.HIGH)
                context.metadata["delimiter_pattern"] = pattern.pattern
                break
        return nxt(context)

    return FnRivet("delimiter_confusion", handler)
