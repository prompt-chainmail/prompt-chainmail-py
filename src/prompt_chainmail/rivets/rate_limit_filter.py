from __future__ import annotations

import threading
import time
from collections.abc import Callable

from prompt_chainmail.rivets.base import FnRivet, NextFn, Rivet
from prompt_chainmail.rivets.types import SecurityFlags
from prompt_chainmail.types import ChainmailContext, ChainmailResult

KeyFn = Callable[[ChainmailContext], str]


def rate_limit_filter(
    max_requests: int | None = None,
    window_ms: float | None = None,
    key_fn: KeyFn | None = None,
    max_keys: int | None = None,
) -> Rivet:
    """Quota filter. Sets blocked when the request cap is hit, not from leftover trust."""
    limit = 100 if max_requests is None else max_requests
    window = 60_000.0 if window_ms is None else float(window_ms)
    resolve_key = key_fn or (lambda _ctx: "global")
    key_cap = 1000 if max_keys is None else max_keys
    requests: dict[str, list[float]] = {}
    lock = threading.Lock()

    def handler(context: ChainmailContext, nxt: NextFn) -> ChainmailResult:
        key = resolve_key(context)
        now = time.time() * 1000.0
        with lock:
            if len(requests) >= key_cap and key not in requests:
                context.flags.add(SecurityFlags.RATE_LIMITED)
                context.set_blocked(True)
                return ChainmailResult(
                    success=False,
                    context=context,
                    processing_time=now - context.start_time,
                )

            timestamps = requests.setdefault(key, [])
            cutoff = now - window
            while timestamps and timestamps[0] < cutoff:
                timestamps.pop(0)

            if len(timestamps) >= limit:
                context.set_blocked(True)
                context.flags.add(SecurityFlags.RATE_LIMITED)
                return ChainmailResult(
                    success=False,
                    context=context,
                    processing_time=now - context.start_time,
                )
            timestamps.append(now)
        return nxt(context)

    return FnRivet("rate_limit_filter", handler)
