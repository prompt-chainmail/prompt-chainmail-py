from __future__ import annotations

import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from prompt_chainmail.rivets.base import FnRivet, NextFn, Rivet
from prompt_chainmail.rivets.types import ThreatLevel
from prompt_chainmail.types import ChainmailContext, ChainmailResult


class TelemetryLogLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARN = "warn"
    ERROR = "error"
    SILENT = "silent"


class TelemetryEventType(Enum):
    PROCESSING_ERROR = "processing_error"
    THREAT_DETECTED = "threat_detected"
    THREAT_BLOCKED = "threat_blocked"
    SECURITY_SCAN = "security_scan"

    def as_str(self) -> str:
        return self.value


@dataclass(slots=True)
class TelemetryData:
    session_id: str
    flags: list[str]
    confidence: float
    processing_time: float
    input_length: int
    blocked: bool
    success: bool


@dataclass(slots=True)
class TelemetryEvent:
    event_type: TelemetryEventType
    threat_level: ThreatLevel
    message: str
    context: TelemetryData
    metadata: dict[str, Any] | None = None
    flags: list[str] | None = None
    risk_score: float | None = None
    attack_types: list[str] | None = None


class TelemetryProvider(Protocol):
    def log_security_event(self, event: TelemetryEvent) -> None: ...
    def track_metric(self, name: str, value: float, tags: dict[str, str] | None = None) -> None: ...
    def capture_error(self, error: str, context: dict[str, Any] | None = None) -> None: ...
    def add_breadcrumb(self, message: str, data: dict[str, Any] | None = None) -> None: ...


class ConsoleTelemetryProvider:
    def log_security_event(self, event: TelemetryEvent) -> None:
        print(
            f"[Security] {event.event_type.as_str()}: {event.message} "
            f"session_id={event.context.session_id} blocked={event.context.blocked} "
            f"confidence={event.context.confidence} flags={event.context.flags}",
            file=sys.stderr,
        )

    def track_metric(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        print(f"[Metric] {name}: {value} tags={tags}", file=sys.stdout)

    def capture_error(self, error: str, context: dict[str, Any] | None = None) -> None:
        print(f"[Error] {error} context={context}", file=sys.stderr)

    def add_breadcrumb(self, message: str, data: dict[str, Any] | None = None) -> None:
        print(f"[Breadcrumb] {message} data={data}", file=sys.stdout)


def create_console_provider() -> TelemetryProvider:
    return ConsoleTelemetryProvider()


def create_sentry_provider(sentry: Any) -> TelemetryProvider:
    class SentryTelemetryProvider:
        def log_security_event(self, event: TelemetryEvent) -> None:
            sentry.capture_message(event.message, extras={"flags": event.flags})

        def track_metric(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
            sentry.set_measurement(name, value)

        def capture_error(self, error: str, context: dict[str, Any] | None = None) -> None:
            sentry.capture_message(error, extras=context)

        def add_breadcrumb(self, message: str, data: dict[str, Any] | None = None) -> None:
            sentry.add_breadcrumb(message=message, data=data)

    return SentryTelemetryProvider()


def get_threat_level_from_confidence_score(confidence: float | None) -> ThreatLevel:
    if confidence is None:
        return ThreatLevel.LOW
    if confidence > 0.8:
        return ThreatLevel.CRITICAL
    if confidence > 0.6:
        return ThreatLevel.HIGH
    if confidence > 0.3:
        return ThreatLevel.MEDIUM
    return ThreatLevel.LOW


def get_log_level_from_confidence(confidence: float) -> TelemetryLogLevel:
    if confidence < 0.5:
        return TelemetryLogLevel.ERROR
    if confidence < 0.7:
        return TelemetryLogLevel.WARN
    return TelemetryLogLevel.INFO


def _default_log_fn(level: TelemetryLogLevel, message: str, data: TelemetryData) -> None:
    if level is TelemetryLogLevel.SILENT:
        return
    line = (
        f"[PromptChainmail] {message} session_id={data.session_id} flags={data.flags} "
        f"confidence={data.confidence} blocked={data.blocked} success={data.success} "
        f"processing_time={data.processing_time} input_length={data.input_length}"
    )
    if level in {TelemetryLogLevel.ERROR, TelemetryLogLevel.WARN}:
        stream = sys.stderr
    else:
        stream = sys.stdout
    print(line, file=stream)


@dataclass
class TelemetryOptions:
    log_fn: Callable[[TelemetryLogLevel, str, TelemetryData], None] | None = None
    track_metrics: bool | None = None
    log_errors: bool | None = None
    provider: TelemetryProvider | None = None


def telemetry(options: TelemetryOptions | None = None) -> Rivet:
    opts = options or TelemetryOptions()
    log_fn = opts.log_fn or _default_log_fn
    track_metrics = True if opts.track_metrics is None else opts.track_metrics
    log_errors = True if opts.log_errors is None else opts.log_errors
    provider = opts.provider

    def handler(context: ChainmailContext, nxt: NextFn) -> ChainmailResult:
        start = time.time() * 1000.0
        if provider is not None:
            provider.add_breadcrumb(
                "Processing started",
                {"session_id": context.session_id, "input_length": len(context.input)},
            )
        result = nxt(context)
        processing_time = time.time() * 1000.0 - start
        telemetry_data = TelemetryData(
            session_id=context.session_id,
            flags=list(context.flags),
            confidence=context.confidence,
            processing_time=processing_time,
            input_length=len(context.input),
            blocked=context.blocked,
            success=result.success,
        )
        if result.error:
            if provider is not None:
                provider.capture_error(
                    result.error, {"session_id": telemetry_data.session_id, "success": False}
                )
                provider.log_security_event(
                    TelemetryEvent(
                        event_type=TelemetryEventType.PROCESSING_ERROR,
                        threat_level=ThreatLevel.LOW,
                        message=f"Processing failed: {result.error}",
                        context=telemetry_data,
                    )
                )
            elif log_errors:
                log_fn(
                    TelemetryLogLevel.ERROR,
                    f"Processing failed: {result.error}",
                    telemetry_data,
                )
            return result

        if provider is not None:
            provider.track_metric(
                "processing_time",
                processing_time,
                {"success": str(result.success), "flags_count": str(len(context.flags))},
            )
            if not result.success or context.flags:
                if context.blocked:
                    event_type = TelemetryEventType.THREAT_BLOCKED
                elif context.flags:
                    event_type = TelemetryEventType.THREAT_DETECTED
                else:
                    event_type = TelemetryEventType.SECURITY_SCAN
                flags = list(context.flags)
                provider.log_security_event(
                    TelemetryEvent(
                        event_type=event_type,
                        threat_level=get_threat_level_from_confidence_score(context.confidence),
                        message=(
                            f"Security check {'passed' if result.success else 'failed'}: "
                            f"{', '.join(flags)}"
                        ),
                        context=telemetry_data,
                        flags=flags,
                        risk_score=context.metadata.get("risk_score")
                        if isinstance(context.metadata.get("risk_score"), (int, float))
                        else None,
                    )
                )
        elif track_metrics:
            log_fn(
                TelemetryLogLevel.INFO,
                f"Processing completed in {processing_time}ms",
                telemetry_data,
            )
            if not result.success or context.flags:
                log_fn(
                    get_log_level_from_confidence(context.confidence),
                    f"Security flags detected: {', '.join(context.flags)}",
                    telemetry_data,
                )
        return result

    return FnRivet("telemetry", handler)
