from __future__ import annotations

import re
from collections.abc import Callable

from prompt_chainmail.rivets.base import NextFn, Rivet
from prompt_chainmail.rivets.code_injection import code_injection
from prompt_chainmail.rivets.condition import condition
from prompt_chainmail.rivets.confidence_filter import confidence_filter
from prompt_chainmail.rivets.delimiter_confusion import delimiter_confusion
from prompt_chainmail.rivets.encoding_detection import encoding_detection
from prompt_chainmail.rivets.http_fetch import (
    HTTP_FETCH_PRIVATE_RANGES,
    HttpFetchOptions,
    http_fetch,
)
from prompt_chainmail.rivets.instruction_hijacking import instruction_hijacking
from prompt_chainmail.rivets.language_detection import language_detection
from prompt_chainmail.rivets.logger import LogLevel, logger
from prompt_chainmail.rivets.pattern_detection import pattern_detection
from prompt_chainmail.rivets.rate_limit_filter import rate_limit_filter
from prompt_chainmail.rivets.role_confusion import role_confusion
from prompt_chainmail.rivets.sanitize import sanitize
from prompt_chainmail.rivets.side_channel import side_channel
from prompt_chainmail.rivets.sql_injection import sql_injection
from prompt_chainmail.rivets.structure_analysis import structure_analysis
from prompt_chainmail.rivets.telemetry import (
    ConsoleTelemetryProvider,
    TelemetryData,
    TelemetryEvent,
    TelemetryEventType,
    TelemetryLogLevel,
    TelemetryOptions,
    TelemetryProvider,
    create_console_provider,
    create_sentry_provider,
    get_log_level_from_confidence,
    get_threat_level_from_confidence_score,
    telemetry,
)
from prompt_chainmail.rivets.template_injection import template_injection
from prompt_chainmail.rivets.tool_use_hijacking import tool_use_hijacking
from prompt_chainmail.rivets.types import SecurityFlags, ThreatLevel
from prompt_chainmail.rivets.untrusted_wrapper import untrusted_wrapper
from prompt_chainmail.rivets.utils import apply_threat_penalty
from prompt_chainmail.types import ChainmailContext


class Rivets:
    @staticmethod
    def sanitize(max_length: int | None = None) -> Rivet:
        return sanitize(max_length)

    @staticmethod
    def pattern_detection(custom_patterns: list[re.Pattern[str]] | None = None) -> Rivet:
        return pattern_detection(custom_patterns)

    @staticmethod
    def confidence_filter(min_threshold: float = 0.5, max_threshold: float | None = None) -> Rivet:
        return confidence_filter(min_threshold, max_threshold)

    @staticmethod
    def encoding_detection() -> Rivet:
        return encoding_detection()

    @staticmethod
    def sql_injection() -> Rivet:
        return sql_injection()

    @staticmethod
    def code_injection() -> Rivet:
        return code_injection()

    @staticmethod
    def delimiter_confusion() -> Rivet:
        return delimiter_confusion()

    @staticmethod
    def template_injection() -> Rivet:
        return template_injection()

    @staticmethod
    def structure_analysis() -> Rivet:
        return structure_analysis()

    @staticmethod
    def language_detection() -> Rivet:
        return language_detection()

    @staticmethod
    def rate_limit_filter(
        max_requests: int | None = None,
        window_ms: float | None = None,
        key_fn: Callable[[ChainmailContext], str] | None = None,
        max_keys: int | None = None,
    ) -> Rivet:
        return rate_limit_filter(max_requests, window_ms, key_fn, max_keys)

    @staticmethod
    def logger(
        level: LogLevel | None = None,
        log_fn: Callable[[ChainmailContext], None] | None = None,
    ) -> Rivet:
        return logger(level, log_fn)

    @staticmethod
    def untrusted_wrapper(
        tag_name: str | None = None, preserve_original: bool | None = None
    ) -> Rivet:
        return untrusted_wrapper(tag_name, preserve_original)

    @staticmethod
    def http_fetch(url: str, options: HttpFetchOptions | None = None) -> Rivet:
        return http_fetch(url, options)

    @staticmethod
    def condition(
        predicate: Callable[[ChainmailContext], bool],
        flag_name: str | None = None,
        confidence_multiplier: float | None = None,
    ) -> Rivet:
        return condition(predicate, flag_name, confidence_multiplier)

    @staticmethod
    def telemetry(options: TelemetryOptions | None = None) -> Rivet:
        return telemetry(options)

    @staticmethod
    def role_confusion(
        languages_limit: int | None = None,
        languages_detection_threshold: float | None = None,
        confidence_threshold: float | None = None,
    ) -> Rivet:
        return role_confusion(languages_limit, languages_detection_threshold, confidence_threshold)

    @staticmethod
    def instruction_hijacking(
        languages_limit: int | None = None,
        languages_detection_threshold: float | None = None,
        confidence_threshold: float | None = None,
    ) -> Rivet:
        return instruction_hijacking(
            languages_limit, languages_detection_threshold, confidence_threshold
        )

    @staticmethod
    def tool_use_hijacking(
        languages_limit: int | None = None,
        languages_detection_threshold: float | None = None,
        confidence_threshold: float | None = None,
    ) -> Rivet:
        return tool_use_hijacking(
            languages_limit, languages_detection_threshold, confidence_threshold
        )

    @staticmethod
    def side_channel(
        languages_limit: int | None = None,
        languages_detection_threshold: float | None = None,
        confidence_threshold: float | None = None,
    ) -> Rivet:
        return side_channel(languages_limit, languages_detection_threshold, confidence_threshold)


__all__ = [
    "HTTP_FETCH_PRIVATE_RANGES",
    "ConsoleTelemetryProvider",
    "HttpFetchOptions",
    "LogLevel",
    "NextFn",
    "Rivet",
    "Rivets",
    "SecurityFlags",
    "TelemetryData",
    "TelemetryEvent",
    "TelemetryEventType",
    "TelemetryLogLevel",
    "TelemetryOptions",
    "TelemetryProvider",
    "ThreatLevel",
    "apply_threat_penalty",
    "code_injection",
    "condition",
    "confidence_filter",
    "create_console_provider",
    "create_sentry_provider",
    "delimiter_confusion",
    "encoding_detection",
    "get_log_level_from_confidence",
    "get_threat_level_from_confidence_score",
    "http_fetch",
    "instruction_hijacking",
    "language_detection",
    "logger",
    "pattern_detection",
    "rate_limit_filter",
    "role_confusion",
    "sanitize",
    "side_channel",
    "sql_injection",
    "structure_analysis",
    "telemetry",
    "template_injection",
    "tool_use_hijacking",
    "untrusted_wrapper",
]
