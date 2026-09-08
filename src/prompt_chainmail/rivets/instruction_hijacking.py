from __future__ import annotations

from prompt_chainmail.rivets.base import Rivet
from prompt_chainmail.rivets.classifier_family import family_rivet
from prompt_chainmail.rivets.types import SecurityFlags
from prompt_chainmail.shared.classifier import ClassifierFamily
from prompt_chainmail.shared.language_detection import (
    detect_lookalike_chars,
    has_language_script_mixing,
)
from prompt_chainmail.types import ChainmailContext

_FLAG_MAP = {
    "instruction_override": SecurityFlags.INSTRUCTION_HIJACKING_OVERRIDE,
    "instruction_forgetting": SecurityFlags.INSTRUCTION_HIJACKING_IGNORE,
    "reset_system": SecurityFlags.INSTRUCTION_HIJACKING_RESET,
    "bypass_security": SecurityFlags.INSTRUCTION_HIJACKING_BYPASS,
    "information_extraction": SecurityFlags.INSTRUCTION_HIJACKING_REVEAL,
}


def instruction_hijacking(
    languages_limit: int | None = None,
    languages_detection_threshold: float | None = None,
    confidence_threshold: float | None = None,
) -> Rivet:
    def apply_flags(
        context: ChainmailContext,
        attack_types: list[str],
        _confidence: float,
        languages: list[tuple[str, float]],
    ) -> None:
        context.flags.add(SecurityFlags.INSTRUCTION_HIJACKING)
        for attack_type in attack_types:
            context.flags.add(
                _FLAG_MAP.get(attack_type, SecurityFlags.INSTRUCTION_HIJACKING_UNKNOWN)
            )
        if len(languages) > 1:
            context.flags.add(SecurityFlags.INSTRUCTION_HIJACKING_MULTILINGUAL_ATTACK)
        if has_language_script_mixing(context.sanitized):
            context.flags.add(SecurityFlags.INSTRUCTION_HIJACKING_SCRIPT_MIXING)
        if detect_lookalike_chars(context.sanitized):
            context.flags.add(SecurityFlags.INSTRUCTION_HIJACKING_LOOKALIKES)

    return family_rivet(
        name="instruction_hijacking",
        family=ClassifierFamily.INSTRUCTION_HIJACKING,
        languages_limit=3 if languages_limit is None else languages_limit,
        languages_detection_threshold=(
            0.1 if languages_detection_threshold is None else languages_detection_threshold
        ),
        confidence_threshold=confidence_threshold,
        apply_attack_flags=apply_flags,
        prefix="instruction_hijacking",
        language_key="instruction_hijacking_detected_language",
    )
