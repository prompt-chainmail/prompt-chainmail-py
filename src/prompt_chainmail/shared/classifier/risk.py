from __future__ import annotations

import json
from functools import cache
from importlib.resources import files
from typing import Any, cast

from prompt_chainmail.shared.classifier.types import RiskCalculationConfig


def _read_config(name: str) -> dict[str, Any]:
    raw = files("prompt_chainmail.shared.configs").joinpath(name).read_text(encoding="utf-8")
    return cast(dict[str, Any], json.loads(raw)["value"])


@cache
def _language_group_map() -> dict[str, str]:
    value = _read_config("language_iso3_to_language_groups.json")
    return {str(key): str(item) for key, item in value.items()}


@cache
def _cybercrime_index() -> dict[str, float]:
    value = _read_config("language_region_cybercrime_index.json")
    return {str(key): float(item) for key, item in value.items()}


@cache
def _fifth_highest_threshold() -> float:
    values = sorted(_cybercrime_index().values(), reverse=True)
    return values[4] if len(values) > 4 else 0.0


def language_group_for_code(language_code: str) -> str:
    return _language_group_map().get(language_code, "eng")


def calculate_language_code_risk_score(
    confidence: float,
    language_group: str,
    attack_type_count: int,
    config: RiskCalculationConfig,
) -> float:
    base_risk = confidence * 100.0
    cybercrime_index_value = _cybercrime_index().get(language_group, config.cybercrime_index_base)
    cybercrime_multiplier = cybercrime_index_value / config.cybercrime_index_base

    calculated_multiplier = attack_type_count / config.attack_type_divisor
    attack_type_multiplier = (
        calculated_multiplier
        if calculated_multiplier < config.max_attack_type_multiplier
        else config.max_attack_type_multiplier
    )

    fifth_highest = _fifth_highest_threshold()
    if fifth_highest <= 0.0:
        fifth_highest = config.fallback_threshold if config.fallback_threshold is not None else 50.0

    risk_boost = (
        config.high_risk_boost
        if attack_type_count > 1 and cybercrime_index_value >= fifth_highest
        else 1.0
    )

    risk_score = base_risk * cybercrime_multiplier * (1.0 + attack_type_multiplier) * risk_boost
    return risk_score if risk_score < config.max_risk_score else config.max_risk_score
