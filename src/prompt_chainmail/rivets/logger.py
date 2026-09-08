from __future__ import annotations

import sys
import time
from collections.abc import Callable
from enum import Enum

from prompt_chainmail.rivets.base import FnRivet, NextFn, Rivet
from prompt_chainmail.types import ChainmailContext, ChainmailResult


class LogLevel(Enum):
    LOG = "log"
    WARN = "warn"
    DEBUG = "debug"
    INFO = "info"


def logger(
    level: LogLevel | None = None,
    log_fn: Callable[[ChainmailContext], None] | None = None,
) -> Rivet:
    used_level = LogLevel.LOG if level is None else level

    def handler(context: ChainmailContext, nxt: NextFn) -> ChainmailResult:
        start = time.time() * 1000.0
        result = nxt(context)
        duration = time.time() * 1000.0 - start
        if log_fn is not None:
            log_fn(context)
        else:
            message = (
                f"[PromptChainmail] flags={list(context.flags)} confidence={context.confidence} "
                f"blocked={context.blocked} duration={duration} input_length={len(context.input)}"
            )
            stream = sys.stderr if used_level is LogLevel.WARN else sys.stdout
            print(message, file=stream)
        return result

    return FnRivet("logger", handler)
