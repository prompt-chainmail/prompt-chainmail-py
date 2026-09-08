from __future__ import annotations

from prompt_chainmail.chainmail import PromptChainmail
from prompt_chainmail.rivets import Rivets


class Chainmails:
    @staticmethod
    def basic(
        max_length: int | None = None, confidence_filter: float | None = None
    ) -> PromptChainmail:
        length = 8000 if max_length is None else max_length
        threshold = 0.6 if confidence_filter is None else confidence_filter
        return (
            PromptChainmail()
            .forge(Rivets.sanitize(length))
            .forge(Rivets.pattern_detection())
            .forge(Rivets.role_confusion())
            .forge(Rivets.delimiter_confusion())
            .forge(Rivets.confidence_filter(threshold))
        )

    @staticmethod
    def advanced(
        max_length: int | None = None, confidence_filter: float | None = None
    ) -> PromptChainmail:
        length = 8000 if max_length is None else max_length
        threshold = 0.6 if confidence_filter is None else confidence_filter
        return (
            PromptChainmail()
            .forge(Rivets.sanitize(length))
            .forge(Rivets.pattern_detection())
            .forge(Rivets.role_confusion())
            .forge(Rivets.delimiter_confusion())
            .forge(Rivets.instruction_hijacking())
            .forge(Rivets.tool_use_hijacking())
            .forge(Rivets.side_channel())
            .forge(Rivets.code_injection())
            .forge(Rivets.sql_injection())
            .forge(Rivets.template_injection())
            .forge(Rivets.encoding_detection())
            .forge(Rivets.structure_analysis())
            .forge(Rivets.confidence_filter(threshold))
            .forge(Rivets.rate_limit_filter())
        )

    @staticmethod
    def development() -> PromptChainmail:
        return Chainmails.advanced().forge(Rivets.logger())

    @staticmethod
    def strict(
        max_length: int | None = None, confidence_filter: float | None = None
    ) -> PromptChainmail:
        length = 8000 if max_length is None else max_length
        threshold = 0.8 if confidence_filter is None else confidence_filter
        return (
            PromptChainmail()
            .forge(Rivets.sanitize(length))
            .forge(Rivets.pattern_detection())
            .forge(Rivets.role_confusion())
            .forge(Rivets.delimiter_confusion())
            .forge(Rivets.instruction_hijacking())
            .forge(Rivets.tool_use_hijacking())
            .forge(Rivets.side_channel())
            .forge(Rivets.code_injection())
            .forge(Rivets.sql_injection())
            .forge(Rivets.template_injection())
            .forge(Rivets.encoding_detection())
            .forge(Rivets.structure_analysis())
            .forge(Rivets.confidence_filter(threshold))
            .forge(Rivets.rate_limit_filter(50, 60_000))
        )
