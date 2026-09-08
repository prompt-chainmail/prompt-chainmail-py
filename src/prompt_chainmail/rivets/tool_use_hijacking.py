from __future__ import annotations

from prompt_chainmail.rivets.base import Rivet
from prompt_chainmail.rivets.classifier_family import family_rivet
from prompt_chainmail.rivets.types import SecurityFlags
from prompt_chainmail.shared.classifier import ClassifierFamily
from prompt_chainmail.types import ChainmailContext


def tool_use_hijacking(
    languages_limit: int | None = None,
    languages_detection_threshold: float | None = None,
    confidence_threshold: float | None = None,
) -> Rivet:
    def apply_flags(
        context: ChainmailContext,
        _attack_types: list[str],
        _confidence: float,
        _languages: list[tuple[str, float]],
    ) -> None:
        context.flags.add(SecurityFlags.TOOL_USE_HIJACKING)

    return family_rivet(
        name="tool_use_hijacking",
        family=ClassifierFamily.TOOL_USE_HIJACKING,
        languages_limit=3 if languages_limit is None else languages_limit,
        languages_detection_threshold=(
            0.1 if languages_detection_threshold is None else languages_detection_threshold
        ),
        confidence_threshold=confidence_threshold,
        apply_attack_flags=apply_flags,
        prefix="tool_use_hijacking",
        language_key="tool_use_hijacking_detected_language",
    )
