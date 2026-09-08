from __future__ import annotations

from prompt_chainmail.rivets.base import FnRivet, NextFn, Rivet
from prompt_chainmail.rivets.types import SecurityFlags
from prompt_chainmail.types import ChainmailContext, ChainmailResult


def untrusted_wrapper(
    tag_name: str | None = None,
    preserve_original: bool | None = None,
) -> Rivet:
    tag = "UNTRUSTED_CONTENT" if tag_name is None else tag_name
    preserve = bool(preserve_original)

    def handler(context: ChainmailContext, nxt: NextFn) -> ChainmailResult:
        if preserve:
            context.metadata["original_content"] = context.sanitized
        context.sanitized = f"<{tag}>\n{context.sanitized}\n</{tag}>"
        context.flags.add(SecurityFlags.UNTRUSTED_WRAPPED)
        return nxt(context)

    return FnRivet("untrusted_wrapper", handler)
