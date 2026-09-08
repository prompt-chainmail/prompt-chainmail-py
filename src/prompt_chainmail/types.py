from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ChainmailContext:
    input: str
    sanitized: str
    flags: set[str] = field(default_factory=set)
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    start_time: float = 0.0
    session_id: str = ""

    def set_blocked(self, blocked: bool) -> None:
        if blocked:
            self.blocked = True


@dataclass(slots=True)
class ChainmailResult:
    success: bool
    context: ChainmailContext
    processing_time: float
    error: str | None = None
