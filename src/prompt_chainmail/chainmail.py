from __future__ import annotations

import asyncio
import time
import uuid
from typing import Self

from prompt_chainmail.rivets.base import Rivet
from prompt_chainmail.types import ChainmailContext, ChainmailResult
from prompt_chainmail.utils import (
    MAX_CHUNK_SIZE,
    MAX_INPUT_SIZE,
    STRING_CHUNKING_THRESHOLD,
    to_chunks,
)


def _now_ms() -> float:
    return time.time() * 1000.0


class PromptChainmail:
    def __init__(self) -> None:
        self._rivets: list[Rivet] = []

    def forge(self, rivet: Rivet) -> Self:
        if any(existing.name() == rivet.name() for existing in self._rivets):
            raise ValueError(
                f"Duplicate rivet: '{rivet.name()}' has already been forged into the chainmail"
            )
        self._rivets.append(rivet)
        return self

    @property
    def length(self) -> int:
        return len(self._rivets)

    def __len__(self) -> int:
        return len(self._rivets)

    def clone(self) -> PromptChainmail:
        cloned = PromptChainmail()
        cloned._rivets = list(self._rivets)
        return cloned

    def protect(self, input: str) -> ChainmailResult:
        start_time = _now_ms()
        session_id = str(uuid.uuid4())

        if input is None:  # type: ignore[comparison-overlap]
            context = ChainmailContext(
                input="",
                sanitized="",
                flags={"invalid_input"},
                blocked=True,
                start_time=start_time,
                session_id=session_id,
            )
            return self._create_result(context, _now_ms() - start_time, f"Invalid input: {input}")

        if len(input) > STRING_CHUNKING_THRESHOLD:
            return self._protect_chunked(input, start_time, session_id)
        return self._protect_string(input, start_time, session_id)

    def protect_bytes(self, input: bytes) -> ChainmailResult:
        return self.protect(input.decode("utf-8", errors="replace"))

    async def protect_async(self, input: str | bytes) -> ChainmailResult:
        if isinstance(input, bytes):
            return await asyncio.to_thread(self.protect_bytes, input)
        return await asyncio.to_thread(self.protect, input)

    def _protect_string(self, input: str, start_time: float, session_id: str) -> ChainmailResult:
        context = ChainmailContext(
            input=input,
            sanitized=input,
            start_time=start_time,
            session_id=session_id,
        )
        if not self._rivets:
            return self._create_result(context, _now_ms() - start_time)
        try:
            return self._run_rivets(context, start_time)
        except Exception as exc:
            context.set_blocked(True)
            return self._create_result(context, _now_ms() - start_time, str(exc))

    def _protect_chunked(self, input: str, start_time: float, session_id: str) -> ChainmailResult:
        chunks = to_chunks(input, MAX_CHUNK_SIZE)
        total_length = sum(len(chunk) for chunk in chunks)
        chunk_count = len(chunks)

        if total_length > MAX_INPUT_SIZE:
            return self._create_stream_result(
                blocked=True,
                chunk_count=chunk_count,
                total_length=total_length,
                stream_flags={"stream_size_exceeded"},
                stream_metadata={"stream_size_limit": MAX_INPUT_SIZE},
                confidence=0.0,
                start_time=start_time,
                session_id=session_id,
            )

        stream_flags: set[str] = set()
        stream_metadata: dict[str, object] = {}
        min_confidence = 1.0
        processed = 0
        seen_length = 0

        for chunk in chunks:
            processed += 1
            seen_length += len(chunk)
            chunk_result = self._protect_one_chunk(chunk, start_time, session_id)
            stream_flags.update(chunk_result.context.flags)
            stream_metadata.update(chunk_result.context.metadata)
            min_confidence = min(min_confidence, chunk_result.context.confidence)
            if chunk_result.context.blocked:
                return self._create_stream_result(
                    True,
                    processed,
                    seen_length,
                    stream_flags,
                    stream_metadata,
                    min_confidence,
                    start_time,
                    session_id,
                )

        return self._create_stream_result(
            False,
            processed,
            seen_length,
            stream_flags,
            stream_metadata,
            min_confidence,
            start_time,
            session_id,
        )

    def _protect_one_chunk(self, chunk: str, start_time: float, session_id: str) -> ChainmailResult:
        context = ChainmailContext(
            input=chunk,
            sanitized=chunk,
            start_time=start_time,
            session_id=session_id,
        )
        if not self._rivets:
            return self._create_result(context, _now_ms() - start_time)
        return self._run_rivets(context, start_time)

    def _run_rivets(self, context: ChainmailContext, start_time: float) -> ChainmailResult:
        index = 0
        rivets = self._rivets

        def nxt(ctx: ChainmailContext) -> ChainmailResult:
            nonlocal index
            if index >= len(rivets):
                return self._create_result(ctx, _now_ms() - start_time)
            rivet = rivets[index]
            index += 1
            return rivet.process(ctx, nxt)

        return nxt(context)

    def _create_stream_result(
        self,
        blocked: bool,
        chunk_count: int,
        total_length: int,
        stream_flags: set[str],
        stream_metadata: dict[str, object],
        confidence: float,
        start_time: float,
        session_id: str,
    ) -> ChainmailResult:
        stream_metadata["chunk_count"] = chunk_count
        stream_metadata["total_length"] = total_length
        stream_desc = f"[Stream: {chunk_count} chunks, {total_length} chars]"
        context = ChainmailContext(
            input=stream_desc,
            sanitized=stream_desc,
            flags=stream_flags,
            confidence=confidence,
            metadata=stream_metadata,
            start_time=start_time,
            session_id=session_id,
        )
        context.set_blocked(blocked)
        return self._create_result(context, _now_ms() - start_time)

    def _create_result(
        self,
        context: ChainmailContext,
        processing_time: float,
        error: str | None = None,
    ) -> ChainmailResult:
        return ChainmailResult(
            success=not context.blocked and error is None,
            context=context,
            processing_time=processing_time,
            error=error,
        )
