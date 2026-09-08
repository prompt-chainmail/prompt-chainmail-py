from __future__ import annotations

from prompt_chainmail.rivets.base import Rivet
from prompt_chainmail.rivets.classifier_family import family_rivet
from prompt_chainmail.rivets.types import SecurityFlags
from prompt_chainmail.shared.classifier import ClassifierFamily
from prompt_chainmail.types import ChainmailContext

_FLAG_MAP = {
    "side_channel_coordination": SecurityFlags.SIDE_CHANNEL_COORDINATION,
    "side_channel_state_write": SecurityFlags.SIDE_CHANNEL_STATE_WRITE,
}


def side_channel(
    languages_limit: int | None = None,
    languages_detection_threshold: float | None = None,
    confidence_threshold: float | None = None,
) -> Rivet:
    def apply_flags(
        context: ChainmailContext,
        attack_types: list[str],
        _confidence: float,
        _languages: list[tuple[str, float]],
    ) -> None:
        context.flags.add(SecurityFlags.SIDE_CHANNEL)
        for attack_type in attack_types:
            flag = _FLAG_MAP.get(attack_type)
            if flag:
                context.flags.add(flag)

    return family_rivet(
        name="side_channel",
        family=ClassifierFamily.SIDE_CHANNEL,
        languages_limit=3 if languages_limit is None else languages_limit,
        languages_detection_threshold=(
            0.1 if languages_detection_threshold is None else languages_detection_threshold
        ),
        confidence_threshold=confidence_threshold,
        apply_attack_flags=apply_flags,
        prefix="side_channel",
        language_key="side_channel_detected_language",
    )
