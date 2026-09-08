from __future__ import annotations

from enum import StrEnum

INSTRUCTION_HIJACKING_LABELS: tuple[str, ...] = (
    "instruction_override",
    "instruction_forgetting",
    "reset_system",
    "bypass_security",
    "information_extraction",
)

ROLE_CONFUSION_LABELS: tuple[str, ...] = (
    "role_assumption",
    "mode_switching",
    "permission_assertion",
    "role_indicator",
)

TOOL_USE_HIJACKING_LABELS: tuple[str, ...] = ("tool_use_hijacking",)

SIDE_CHANNEL_LABELS: tuple[str, ...] = (
    "side_channel_coordination",
    "side_channel_state_write",
)

# Full label order matching manifest.json and the subtype output tensor.
CLASSIFIER_LABELS: tuple[str, ...] = (
    *INSTRUCTION_HIJACKING_LABELS,
    *ROLE_CONFUSION_LABELS,
    *TOOL_USE_HIJACKING_LABELS,
    *SIDE_CHANNEL_LABELS,
)

type ClassifierLabel = str


class ClassifierFamily(StrEnum):
    INSTRUCTION_HIJACKING = "instruction_hijacking"
    ROLE_CONFUSION = "role_confusion"
    TOOL_USE_HIJACKING = "tool_use_hijacking"
    SIDE_CHANNEL = "side_channel"


def labels_for_family(family: ClassifierFamily) -> tuple[str, ...]:
    if family is ClassifierFamily.INSTRUCTION_HIJACKING:
        return INSTRUCTION_HIJACKING_LABELS
    if family is ClassifierFamily.ROLE_CONFUSION:
        return ROLE_CONFUSION_LABELS
    if family is ClassifierFamily.TOOL_USE_HIJACKING:
        return TOOL_USE_HIJACKING_LABELS
    return SIDE_CHANNEL_LABELS
