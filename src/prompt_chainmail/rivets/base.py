from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from prompt_chainmail.types import ChainmailContext, ChainmailResult

NextFn = Callable[[ChainmailContext], ChainmailResult]


class Rivet(Protocol):
    def name(self) -> str: ...

    def process(self, context: ChainmailContext, nxt: NextFn) -> ChainmailResult: ...


class FnRivet:
    def __init__(
        self,
        name: str,
        handler: Callable[[ChainmailContext, NextFn], ChainmailResult],
    ) -> None:
        self._name = name
        self._handler = handler

    def name(self) -> str:
        return self._name

    def process(self, context: ChainmailContext, nxt: NextFn) -> ChainmailResult:
        return self._handler(context, nxt)
