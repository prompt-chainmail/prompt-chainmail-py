from __future__ import annotations

from importlib.resources import files


def read_config_text(name: str) -> str:
    return files(__package__).joinpath(name).read_text(encoding="utf-8")


CLASSIFIER_DETECTOR_JSON = "classifier_detector.json"
LANGUAGE_ISO3_TO_LANGUAGE_GROUPS_JSON = "language_iso3_to_language_groups.json"
LANGUAGE_REGION_CYBERCRIME_INDEX_JSON = "language_region_cybercrime_index.json"

__all__ = [
    "CLASSIFIER_DETECTOR_JSON",
    "LANGUAGE_ISO3_TO_LANGUAGE_GROUPS_JSON",
    "LANGUAGE_REGION_CYBERCRIME_INDEX_JSON",
    "read_config_text",
]
