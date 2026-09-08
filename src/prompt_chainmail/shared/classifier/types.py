from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Quantization:
    format: str
    method: str


@dataclass(slots=True)
class LanguageRecall:
    recall: float


@dataclass(slots=True)
class Metrics:
    macro_f1: float
    macro_recall: float
    benign_false_positive_rate: float
    attack_precision: float
    attack_recall: float
    attack_f1: float
    per_language: dict[str, LanguageRecall]


@dataclass(slots=True)
class ClassifierManifest:
    attack_threshold: float
    thresholds: dict[str, float]
    schema_version: int
    artifact_version: str
    model_sha256: str
    model_size_bytes: int
    labels: list[str]
    normalization_version: str
    window_size_bytes: int
    window_stride_bytes: int
    corpus_revision: str
    quantization: Quantization
    metrics: Metrics
    release_quality: bool
    gate_failures: list[str]


@dataclass(slots=True)
class ClassifierMatch:
    label: str
    probability: float
    window_index: int
    window_start_byte: int
    window_end_byte: int
    model_version: str


@dataclass(slots=True)
class SemanticDetectionResult:
    is_attack: bool
    attack_types: list[str]
    confidence: float
    risk_score: float
    detected_language: str
    details: list[str]
    matches: list[ClassifierMatch] | None = None
    detector_error: str | None = None


@dataclass(slots=True)
class ClassifierClassification:
    attack_probability: float
    probabilities: dict[str, float]
    matches: list[ClassifierMatch]
    window_errors: int


@dataclass(slots=True)
class RiskCalculationConfig:
    cybercrime_index_base: float
    max_attack_type_multiplier: float
    attack_type_divisor: float
    high_risk_boost: float
    max_risk_score: float
    fallback_threshold: float | None = None


@dataclass(slots=True)
class ClassifierDetectionConfig:
    risk_calculation: RiskCalculationConfig


@dataclass(slots=True)
class ClassifyFamilyOptions:
    confidence_threshold: float | None = field(default=None)
