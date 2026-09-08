from __future__ import annotations

import threading
from typing import Protocol

from prompt_chainmail.shared.classifier.backend import ClassifierBackend
from prompt_chainmail.shared.classifier.config import ClassifierConfigLoader
from prompt_chainmail.shared.classifier.labels import ClassifierFamily, labels_for_family
from prompt_chainmail.shared.classifier.manifest import CLASSIFIER_MANIFEST
from prompt_chainmail.shared.classifier.risk import (
    calculate_language_code_risk_score,
    language_group_for_code,
)
from prompt_chainmail.shared.classifier.session import ClassifierError
from prompt_chainmail.shared.classifier.types import (
    ClassifierClassification,
    ClassifyFamilyOptions,
    SemanticDetectionResult,
)


class _ClassifierLike(Protocol):
    def classify(self, text: str) -> ClassifierClassification: ...


def _empty_result(language_code: str) -> SemanticDetectionResult:
    return SemanticDetectionResult(
        is_attack=False,
        attack_types=[],
        confidence=0.0,
        risk_score=0.0,
        detected_language=language_code,
        details=[],
        matches=[],
        detector_error=None,
    )


class CombinedClassifier:
    """Family-filtered wrapper around the shared classifier backend."""

    def __init__(self, backend: _ClassifierLike | None = None) -> None:
        self._backend = backend if backend is not None else ClassifierBackend()

    @classmethod
    def with_backend(cls, backend: _ClassifierLike) -> CombinedClassifier:
        return cls(backend)

    def classify_family(
        self,
        text: str,
        language_code: str,
        family: ClassifierFamily,
        options: ClassifyFamilyOptions | None = None,
    ) -> SemanticDetectionResult:
        if text.strip() == "":
            return _empty_result(language_code)

        opts = options or ClassifyFamilyOptions()
        try:
            classification = self._backend.classify(text)
        except ClassifierError as error:
            result = _empty_result(language_code)
            result.details = [f"Classifier detection error: {error.code}"]
            result.detector_error = error.code
            return result
        except Exception:
            result = _empty_result(language_code)
            result.details = ["Classifier detection error: unknown_error"]
            result.detector_error = "unknown_error"
            return result

        family_labels = set(labels_for_family(family))
        language_group = language_group_for_code(language_code)
        risk_config = ClassifierConfigLoader.get(family)

        matches = [item for item in classification.matches if item.label in family_labels]
        attack_types = sorted({item.label for item in matches})

        confidence = classification.attack_probability
        passes_attack_threshold = confidence >= CLASSIFIER_MANIFEST.attack_threshold
        passes_confidence_floor = (
            True if opts.confidence_threshold is None else confidence >= opts.confidence_threshold
        )
        passes_attack_gate = (
            passes_attack_threshold
            or family is ClassifierFamily.TOOL_USE_HIJACKING
            or family is ClassifierFamily.SIDE_CHANNEL
        )
        is_attack = passes_attack_gate and len(attack_types) > 0 and passes_confidence_floor

        risk_score = (
            calculate_language_code_risk_score(
                confidence,
                language_group,
                len(attack_types),
                risk_config.risk_calculation,
            )
            if is_attack
            else 0.0
        )

        details = [
            (
                f"Classifier label {item.label} probability "
                f"{item.probability:.3f} (window {item.window_index})"
            )
            for item in matches
        ]

        return SemanticDetectionResult(
            is_attack=is_attack,
            attack_types=attack_types if is_attack else [],
            confidence=confidence,
            risk_score=risk_score,
            detected_language=language_group if language_group else language_code,
            details=details,
            matches=matches,
            detector_error=None,
        )


_shared_lock = threading.Lock()
_shared: CombinedClassifier | None = None


def get_combined_classifier() -> CombinedClassifier:
    global _shared
    with _shared_lock:
        if _shared is None:
            _shared = CombinedClassifier()
        return _shared


def set_combined_classifier_for_tests(classifier: CombinedClassifier) -> None:
    global _shared
    with _shared_lock:
        _shared = classifier


def reset_combined_classifier_for_tests() -> None:
    global _shared
    with _shared_lock:
        _shared = None
