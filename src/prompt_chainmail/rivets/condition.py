from __future__ import annotations

from collections.abc import Callable

from prompt_chainmail.rivets.base import FnRivet, NextFn, Rivet
from prompt_chainmail.rivets.types import ThreatLevel
from prompt_chainmail.rivets.utils import apply_threat_penalty
from prompt_chainmail.types import ChainmailContext, ChainmailResult


def condition(
    predicate: Callable[[ChainmailContext], bool],
    flag_name: str | None = None,
    confidence_multiplier: float | None = None,
) -> Rivet:
    name = "custom_condition" if flag_name is None else flag_name
    multiplier = 0.8 if confidence_multiplier is None else confidence_multiplier

    def handler(context: ChainmailContext, nxt: NextFn) -> ChainmailResult:
        if predicate(context):
            context.flags.add(name)
            if multiplier <= 0.5:
                penalty = ThreatLevel.HIGH
            elif multiplier <= 0.7:
                penalty = ThreatLevel.MEDIUM
            else:
                penalty = ThreatLevel.LOW
            apply_threat_penalty(context, penalty)
        return nxt(context)

    return FnRivet("condition", handler)
