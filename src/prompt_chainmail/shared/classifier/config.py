from __future__ import annotations

import json
from functools import cache
from importlib.resources import files

from prompt_chainmail.shared.classifier.labels import ClassifierFamily
from prompt_chainmail.shared.classifier.types import (
    ClassifierDetectionConfig,
    RiskCalculationConfig,
)


def _load_detector_config() -> dict[str, ClassifierDetectionConfig]:
    raw = (
        files("prompt_chainmail.shared.configs")
        .joinpath("classifier_detector.json")
        .read_text(encoding="utf-8")
    )
    wrapper = json.loads(raw)
    value = wrapper["value"]
    parsed: dict[str, ClassifierDetectionConfig] = {}
    for key, payload in value.items():
        risk = payload["risk_calculation"]
        parsed[key] = ClassifierDetectionConfig(
            risk_calculation=RiskCalculationConfig(
                cybercrime_index_base=float(risk["cybercrime_index_base"]),
                max_attack_type_multiplier=float(risk["max_attack_type_multiplier"]),
                attack_type_divisor=float(risk["attack_type_divisor"]),
                high_risk_boost=float(risk["high_risk_boost"]),
                max_risk_score=float(risk["max_risk_score"]),
                fallback_threshold=(
                    float(risk["fallback_threshold"]) if "fallback_threshold" in risk else None
                ),
            )
        )
    return parsed


@cache
def _detector_config() -> dict[str, ClassifierDetectionConfig]:
    return _load_detector_config()


class ClassifierConfigLoader:
    @staticmethod
    def get(family: ClassifierFamily) -> ClassifierDetectionConfig:
        key = str(family)
        config = _detector_config().get(key)
        if config is None:
            raise KeyError(f"missing classifier_detector config for {key}")
        return config
