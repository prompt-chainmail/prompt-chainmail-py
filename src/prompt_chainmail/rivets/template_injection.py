from __future__ import annotations

import re
from functools import lru_cache

from prompt_chainmail.rivets.base import FnRivet, NextFn, Rivet
from prompt_chainmail.rivets.types import SecurityFlags, ThreatLevel
from prompt_chainmail.rivets.utils import apply_threat_penalty
from prompt_chainmail.types import ChainmailContext, ChainmailResult

_SOURCES = (
    r"\{\{.*\}\}",
    r"\$\{.*\}",
    r"<%.*%>",
    r"\[\[.*\]\]",
    r"#\{.*\}",
    r"\{%.*%\}",
    r"(?i)\{php\}.*\{/php\}",
    r"(?i)\{literal\}.*\{/literal\}",
    r"(?i)\{if.*\}.*\{/if\}",
)


@lru_cache(maxsize=1)
def _patterns() -> list[re.Pattern[str]]:
    return [re.compile(src) for src in _SOURCES]


def template_injection() -> Rivet:
    def handler(context: ChainmailContext, nxt: NextFn) -> ChainmailResult:
        for pattern in _patterns():
            if pattern.search(context.sanitized):
                context.flags.add(SecurityFlags.TEMPLATE_INJECTION)
                apply_threat_penalty(context, ThreatLevel.HIGH)
                context.metadata["template_pattern"] = pattern.pattern
                break
        return nxt(context)

    return FnRivet("template_injection", handler)
