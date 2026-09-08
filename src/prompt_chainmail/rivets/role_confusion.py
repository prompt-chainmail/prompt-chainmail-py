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

_HIGH_RISK = 0.7

_FLAG_MAP = {
    "role_assumption": SecurityFlags.ROLE_CONFUSION_ROLE_ASSUMPTION,
    "mode_switching": SecurityFlags.ROLE_CONFUSION_MODE_SWITCHING,
    "permission_assertion": SecurityFlags.ROLE_CONFUSION_PERMISSION_ASSERTION,
    "role_indicator": SecurityFlags.ROLE_CONFUSION_ROLE_INDICATOR,
}


def role_confusion(
    languages_limit: int | None = None,
    languages_detection_threshold: float | None = None,
    confidence_threshold: float | None = None,
) -> Rivet:
    def apply_flags(
        context: ChainmailContext,
        attack_types: list[str],
        confidence: float,
        languages: list[tuple[str, float]],
    ) -> None:
        context.flags.add(SecurityFlags.ROLE_CONFUSION)
        for attack_type in attack_types:
            flag = _FLAG_MAP.get(attack_type)
            if flag:
                context.flags.add(flag)
        if confidence > _HIGH_RISK and len(attack_types) > 1:
            context.flags.add(SecurityFlags.ROLE_CONFUSION_HIGH_RISK_ROLE)
        if len(languages) > 1:
            context.flags.add(SecurityFlags.ROLE_CONFUSION_MULTILINGUAL_ATTACK)
        if has_language_script_mixing(context.sanitized):
            context.flags.add(SecurityFlags.ROLE_CONFUSION_SCRIPT_MIXING)
        if detect_lookalike_chars(context.sanitized):
            context.flags.add(SecurityFlags.ROLE_CONFUSION_LOOKALIKE_CHARACTERS)

    return family_rivet(
        name="role_confusion",
        family=ClassifierFamily.ROLE_CONFUSION,
        languages_limit=3 if languages_limit is None else languages_limit,
        languages_detection_threshold=(
            0.6 if languages_detection_threshold is None else languages_detection_threshold
        ),
        confidence_threshold=confidence_threshold,
        apply_attack_flags=apply_flags,
        prefix="role_confusion",
        language_key="role_confusion_dominant_language",
    )
