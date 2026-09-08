from __future__ import annotations

from prompt_chainmail.rivets.base import FnRivet, NextFn, Rivet
from prompt_chainmail.shared.language_detection import LanguageDetector
from prompt_chainmail.types import ChainmailContext, ChainmailResult


def language_detection() -> Rivet:
    detector = LanguageDetector()

    def handler(context: ChainmailContext, nxt: NextFn) -> ChainmailResult:
        detected = detector.detect(context.sanitized)
        context.metadata["detected_languages"] = [[code, score] for code, score in detected]
        return nxt(context)

    return FnRivet("language_detection", handler)
