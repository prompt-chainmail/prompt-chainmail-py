from prompt_chainmail import (
    HttpFetchOptions,
    PromptChainmail,
    Rivets,
    SecurityFlags,
    TelemetryOptions,
    create_console_provider,
)


def test_rate_limit_filter_eventually_blocks() -> None:
    mail = PromptChainmail().forge(Rivets.rate_limit_filter(2, 60_000))
    r1 = mail.protect("test 1")
    r2 = mail.protect("test 2")
    r3 = mail.protect("test 3")
    assert r1.success
    assert r2.success
    assert not r3.success
    assert r3.context.blocked
    assert SecurityFlags.RATE_LIMITED in r3.context.flags


def test_condition_predicate_runs_and_skips() -> None:
    mail = PromptChainmail().forge(
        Rivets.condition(lambda ctx: "secret" in ctx.sanitized, "contains_secret", 0.5)
    )
    hit = mail.protect("This contains a secret word")
    assert "contains_secret" in hit.context.flags
    assert hit.context.confidence < 1.0
    miss = mail.protect("Nothing to see here")
    assert "contains_secret" not in miss.context.flags
    assert miss.context.confidence == 1.0


def test_untrusted_wrapper_wraps_sanitized() -> None:
    result = PromptChainmail().forge(Rivets.untrusted_wrapper()).protect("Some user input")
    assert result.context.sanitized == (
        "<UNTRUSTED_CONTENT>\nSome user input\n</UNTRUSTED_CONTENT>"
    )
    assert SecurityFlags.UNTRUSTED_WRAPPED in result.context.flags


def test_logger_does_not_break_pipeline() -> None:
    called = {"value": False}
    mail = (
        PromptChainmail()
        .forge(Rivets.sanitize())
        .forge(Rivets.logger(log_fn=lambda _ctx: called.__setitem__("value", True)))
    )
    assert mail.protect("test input").success
    assert called["value"]


def test_telemetry_console_provider_does_not_break() -> None:
    mail = PromptChainmail().forge(
        Rivets.telemetry(
            TelemetryOptions(
                provider=create_console_provider(),
                track_metrics=True,
                log_errors=True,
            )
        )
    )
    result = mail.protect("Hello world")
    assert result.success
    assert not result.context.blocked


def test_http_fetch_without_httpx_fail_opens() -> None:
    result = (
        PromptChainmail()
        .forge(Rivets.http_fetch("https://example.com", HttpFetchOptions()))
        .protect("payload")
    )
    assert result.success
    assert (
        SecurityFlags.HTTP_ERROR in result.context.flags
        or SecurityFlags.HTTP_SUCCESS in result.context.flags
    )
