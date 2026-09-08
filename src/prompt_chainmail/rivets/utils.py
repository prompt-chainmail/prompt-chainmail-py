from __future__ import annotations

from prompt_chainmail.rivets.types import ThreatLevel
from prompt_chainmail.types import ChainmailContext


def apply_threat_penalty(context: ChainmailContext, level: ThreatLevel) -> None:
    confidence = context.confidence if context.confidence == context.confidence else 1.0
    base_penalty = float(level)
    adjusted_penalty = base_penalty * 1.0

    flag_count = float(len(context.flags))
    flag_scaling = min(2.5, 1.0 + flag_count * 0.025)
    adjusted_penalty *= flag_scaling

    content_length = float(len(context.sanitized))
    if content_length > 1000:
        length_scaling = max(0.5, 1.0 - content_length / 10000.0)
        adjusted_penalty *= length_scaling

    result = max(0.0, confidence - adjusted_penalty)
    context.confidence = round(result * 1000.0) / 1000.0
