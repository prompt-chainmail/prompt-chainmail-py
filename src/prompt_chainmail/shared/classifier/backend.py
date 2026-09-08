from __future__ import annotations

import threading

import numpy as np

from prompt_chainmail.shared.classifier.cache import BoundedCache
from prompt_chainmail.shared.classifier.labels import CLASSIFIER_LABELS
from prompt_chainmail.shared.classifier.normalize import window_classifier_ranges
from prompt_chainmail.shared.classifier.session import (
    ClassifierError,
    ClassifierSessionHandle,
    get_classifier_session,
)
from prompt_chainmail.shared.classifier.types import (
    ClassifierClassification,
    ClassifierMatch,
)

DEFAULT_CACHE_SIZE = 256


def _empty_probabilities() -> dict[str, float]:
    return {label: 0.0 for label in CLASSIFIER_LABELS}


def _as_float_vector(value: object, name: str) -> list[float]:
    if value is None:
        raise ClassifierError(
            "missing_output",
            f"Classifier session output is missing the '{name}' tensor",
        )
    try:
        array = np.asarray(value, dtype=np.float64).reshape(-1)
    except (TypeError, ValueError) as exc:
        raise ClassifierError("missing_output", f"Failed to extract {name}: {exc}") from exc
    return [float(item) for item in array]


def _run_window(
    handle: ClassifierSessionHandle,
    window: bytes,
    window_size_bytes: int,
) -> tuple[float, list[float]]:
    ids = np.zeros((1, window_size_bytes), dtype=np.int64)
    mask = np.zeros((1, window_size_bytes), dtype=np.int64)
    for index, byte in enumerate(window):
        ids[0, index] = int(byte)
        mask[0, index] = 1

    try:
        outputs = handle.run(
            {
                "input_ids": ids,
                "attention_mask": mask,
            }
        )
    except ClassifierError:
        raise
    except Exception as exc:
        raise ClassifierError(
            "window_classification_failed",
            f"session.run failed: {exc}",
        ) from exc

    if "attack_probability" not in outputs:
        raise ClassifierError(
            "missing_output",
            "Classifier session output is missing the 'attack_probability' tensor",
        )
    if "subtype_probabilities" not in outputs:
        raise ClassifierError(
            "missing_output",
            "Classifier session output is missing the 'subtype_probabilities' tensor",
        )

    attack = _as_float_vector(outputs["attack_probability"], "attack_probability")
    subtype = _as_float_vector(outputs["subtype_probabilities"], "subtype_probabilities")
    return (attack[0] if attack else 0.0, subtype)


class ClassifierBackend:
    """Windowed byte-level ONNX classification with max-pool aggregation."""

    def __init__(self, cache_size: int = DEFAULT_CACHE_SIZE) -> None:
        self._cache = BoundedCache[str, ClassifierClassification](cache_size)
        self._cache_lock = threading.Lock()

    def classify(self, text: str) -> ClassifierClassification:
        with self._cache_lock:
            cached = self._cache.get(text)
            if cached is not None:
                return cached

        classification = self._run_inference(text)

        with self._cache_lock:
            self._cache.set(text, classification)
        return classification

    def _run_inference(self, text: str) -> ClassifierClassification:
        if text.strip() == "":
            return ClassifierClassification(
                attack_probability=0.0,
                probabilities=_empty_probabilities(),
                matches=[],
                window_errors=0,
            )

        handle = get_classifier_session()
        manifest = handle.manifest
        try:
            windows = window_classifier_ranges(
                text,
                manifest.window_size_bytes,
                manifest.window_stride_bytes,
            )
        except ValueError as exc:
            raise ClassifierError("window_error", str(exc)) from exc

        attack_probability = 0.0
        probabilities = _empty_probabilities()
        matches: list[ClassifierMatch] = []
        window_errors = 0
        first_window_error: ClassifierError | None = None

        for window_index, window in enumerate(windows):
            try:
                window_attack, subtype = _run_window(
                    handle, window.bytes, manifest.window_size_bytes
                )
            except ClassifierError as exc:
                window_errors += 1
                if first_window_error is None:
                    first_window_error = exc
                continue

            if window_attack > attack_probability:
                attack_probability = window_attack

            for label_index, label in enumerate(CLASSIFIER_LABELS):
                probability = subtype[label_index] if label_index < len(subtype) else 0.0
                if probability > probabilities[label]:
                    probabilities[label] = probability
                threshold = manifest.thresholds.get(label, 1.0)
                if probability >= threshold:
                    matches.append(
                        ClassifierMatch(
                            label=label,
                            probability=probability,
                            window_index=window_index,
                            window_start_byte=window.start,
                            window_end_byte=window.end,
                            model_version=manifest.artifact_version,
                        )
                    )

        if windows and window_errors == len(windows):
            raise first_window_error or ClassifierError(
                "window_classification_failed",
                "All classifier windows failed to produce output",
            )

        return ClassifierClassification(
            attack_probability=attack_probability,
            probabilities=probabilities,
            matches=matches,
            window_errors=window_errors,
        )

    def clear_cache(self) -> None:
        with self._cache_lock:
            self._cache.clear()
