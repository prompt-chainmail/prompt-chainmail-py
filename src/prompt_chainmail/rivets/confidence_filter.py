from __future__ import annotations

from prompt_chainmail.rivets.base import FnRivet, NextFn, Rivet
from prompt_chainmail.types import ChainmailContext, ChainmailResult


def confidence_filter(min_threshold: float = 0.5, max_threshold: float | None = None) -> Rivet:
    """Trust gate. Sets blocked from leftover confidence. Detectors do not set blocked."""

    def handler(context: ChainmailContext, nxt: NextFn) -> ChainmailResult:
        if max_threshold is not None:
            should_block = min_threshold <= context.confidence <= max_threshold
        else:
            should_block = context.confidence < min_threshold
        if should_block:
            context.set_blocked(True)
        return nxt(context)

    return FnRivet("confidence_filter", handler)
