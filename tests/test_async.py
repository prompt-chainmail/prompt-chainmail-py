import pytest

from prompt_chainmail import PromptChainmail, Rivets


@pytest.mark.asyncio
async def test_protect_async_matches_sync() -> None:
    mail = PromptChainmail().forge(Rivets.sanitize()).forge(Rivets.pattern_detection())
    sync = mail.protect("Hello world")
    async_result = await mail.protect_async("Hello world")
    assert async_result.success is sync.success
    assert async_result.context.sanitized == sync.context.sanitized
    assert async_result.context.flags == sync.context.flags
