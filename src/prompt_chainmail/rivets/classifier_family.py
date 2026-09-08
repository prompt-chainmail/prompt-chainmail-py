from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, is_dataclass

from prompt_chainmail.rivets.base import FnRivet, NextFn, Rivet
from prompt_chainmail.rivets.types import SecurityFlags, ThreatLevel
from prompt_chainmail.rivets.utils import apply_threat_penalty
from prompt_chainmail.shared.classifier import (
    ClassifierFamily,
    ClassifyFamilyOptions,
    CombinedClassifier,
    get_combined_classifier,
)
from prompt_chainmail.shared.language_detection import (
    LanguageDetector,
    detect_lookalike_chars,
    has_language_script_mixing,
)
from prompt_chainmail.types import ChainmailContext, ChainmailResult

_DEFAULT_LANGUAGE = "eng"


def _threat_from_confidence(confidence: float) -> ThreatLevel:
    if confidence > 0.7:
        return ThreatLevel.CRITICAL
    if confidence > 0.5:
        return ThreatLevel.HIGH
    return ThreatLevel.MEDIUM


def family_rivet(
    *,
    name: str,
    family: ClassifierFamily,
    languages_limit: int,
    languages_detection_threshold: float,
    confidence_threshold: float | None,
    apply_attack_flags: Callable[
        [ChainmailContext, list[str], float, list[tuple[str, float]]], None
    ],
    prefix: str,
    language_key: str,
    classifier: CombinedClassifier | None = None,
) -> Rivet:
    detector = LanguageDetector()
    used = classifier or get_combined_classifier()

    def handler(context: ChainmailContext, nxt: NextFn) -> ChainmailResult:
        if not context.input.strip():
            return nxt(context)

        languages = [
            pair
            for pair in detector.detect(context.input)
            if pair[1] > languages_detection_threshold
        ]
        if not languages:
            languages = [(_DEFAULT_LANGUAGE, 0.1)]

        top_languages = languages[:languages_limit]
        has_script_mixing = has_language_script_mixing(context.sanitized)
        has_lookalikes = detect_lookalike_chars(context.sanitized)
        primary_language = top_languages[0][0]

        result = used.classify_family(
            context.sanitized,
            primary_language,
            family,
            ClassifyFamilyOptions(confidence_threshold=confidence_threshold),
        )

        if result.is_attack:
            apply_attack_flags(context, result.attack_types, result.confidence, languages)
            if result.confidence >= 0.4:
                apply_threat_penalty(context, _threat_from_confidence(result.confidence))
            context.metadata[f"{prefix}_detected"] = True
            context.metadata[f"{prefix}_attack_types"] = list(result.attack_types)
        else:
            context.metadata[f"{prefix}_detected"] = False
            context.metadata[f"{prefix}_attack_types"] = []

        context.metadata[f"{prefix}_confidence"] = result.confidence
        context.metadata[f"{prefix}_risk_score"] = result.risk_score
        context.metadata[language_key] = primary_language
        context.metadata[f"{prefix}_detected_languages"] = [code for code, _ in top_languages]
        matches = result.matches or []
        context.metadata[f"{prefix}_matches"] = [
            asdict(match) if is_dataclass(match) else match for match in matches
        ]
        context.metadata["has_script_mixing"] = has_script_mixing
        context.metadata["has_lookalikes"] = has_lookalikes

        if result.detector_error:
            context.flags.add(SecurityFlags.CLASSIFIER_UNAVAILABLE)
            context.metadata[f"{prefix}_detector_error"] = result.detector_error

        return nxt(context)

    return FnRivet(name, handler)
