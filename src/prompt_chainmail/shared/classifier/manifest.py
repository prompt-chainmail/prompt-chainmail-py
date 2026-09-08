from __future__ import annotations

import json
import re
from importlib.resources import files
from typing import Any, Never, cast

from prompt_chainmail.shared.classifier.labels import CLASSIFIER_LABELS
from prompt_chainmail.shared.classifier.types import (
    ClassifierManifest,
    LanguageRecall,
    Metrics,
    Quantization,
)

_SHA256_HEX_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAX_MODEL_SIZE_BYTES = 10 * 1024 * 1024
_NORMALIZATION_VERSION = "nfkc-whitespace-lower-v1"
_QUANTIZATION_ERROR = (
    "Classifier manifest quantization must be { format: 'INT8' | 'FLOAT32', method: string }"
)


class ClassifierManifestError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def _is_probability(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and 0.0 <= float(value) <= 1.0
    )


def _fail(message: str) -> Never:
    raise ClassifierManifestError(message)


def validate_manifest(candidate: object) -> ClassifierManifest:
    if not isinstance(candidate, dict):
        _fail("Classifier manifest must be an object")

    obj = cast(dict[str, Any], candidate)

    schema_version = obj.get("schema_version")
    if not isinstance(schema_version, int) or isinstance(schema_version, bool):
        _fail("Classifier manifest schema_version missing")
    if schema_version != 1:
        _fail(f"Unsupported classifier manifest schema_version: {schema_version}")

    artifact_version = obj.get("artifact_version")
    if not isinstance(artifact_version, str) or artifact_version == "":
        _fail("Classifier manifest artifact_version must be a non-empty string")

    model_sha256 = obj.get("model_sha256")
    if not isinstance(model_sha256, str) or _SHA256_HEX_PATTERN.fullmatch(model_sha256) is None:
        _fail("Classifier manifest model_sha256 must be a 64-character hex string")

    model_size_bytes = obj.get("model_size_bytes")
    if not isinstance(model_size_bytes, int) or isinstance(model_size_bytes, bool):
        _fail("Classifier manifest model_size_bytes must be between 1 byte and 10 MiB")
    if model_size_bytes <= 0 or model_size_bytes > _MAX_MODEL_SIZE_BYTES:
        _fail("Classifier manifest model_size_bytes must be between 1 byte and 10 MiB")

    labels = obj.get("labels")
    if (
        not isinstance(labels, list)
        or len(labels) != len(CLASSIFIER_LABELS)
        or any(label != expected for label, expected in zip(labels, CLASSIFIER_LABELS, strict=True))
    ):
        _fail(f"Classifier manifest labels must exactly equal {list(CLASSIFIER_LABELS)} in order")

    normalization_version = obj.get("normalization_version")
    if normalization_version != _NORMALIZATION_VERSION:
        _fail(f"Unsupported classifier normalization_version: {normalization_version}")

    window_size_bytes = obj.get("window_size_bytes")
    if (
        not isinstance(window_size_bytes, int)
        or isinstance(window_size_bytes, bool)
        or window_size_bytes <= 0
    ):
        _fail("Classifier manifest window_size_bytes must be a positive number")

    window_stride_bytes = obj.get("window_stride_bytes")
    if (
        not isinstance(window_stride_bytes, int)
        or isinstance(window_stride_bytes, bool)
        or window_stride_bytes <= 0
    ):
        _fail("Classifier manifest window_stride_bytes must be a positive number")

    thresholds = obj.get("thresholds")
    if not isinstance(thresholds, dict):
        _fail("Classifier manifest thresholds must be an object")
    parsed_thresholds: dict[str, float] = {}
    for label in CLASSIFIER_LABELS:
        value = thresholds.get(label)
        if not _is_probability(value):
            _fail(f"Classifier manifest thresholds.{label} must be a number between 0 and 1")
        parsed_thresholds[label] = float(value)

    attack_threshold = obj.get("attack_threshold")
    if not _is_probability(attack_threshold):
        _fail("Classifier manifest attack_threshold must be a number between 0 and 1")

    corpus_revision = obj.get("corpus_revision")
    if not isinstance(corpus_revision, str) or corpus_revision == "":
        _fail("Classifier manifest corpus_revision must be a non-empty string")

    quantization = obj.get("quantization")
    if not isinstance(quantization, dict):
        _fail(_QUANTIZATION_ERROR)
    q_format = quantization.get("format")
    q_method = quantization.get("method")
    if q_format not in {"INT8", "FLOAT32"} or not isinstance(q_method, str) or q_method == "":
        _fail(_QUANTIZATION_ERROR)

    metrics = obj.get("metrics")
    metric_keys = (
        "macro_f1",
        "macro_recall",
        "benign_false_positive_rate",
        "attack_precision",
        "attack_recall",
        "attack_f1",
    )
    if not isinstance(metrics, dict) or not all(
        _is_probability(metrics.get(key)) for key in metric_keys
    ):
        _fail("Classifier manifest metrics are missing or malformed")
    per_language = metrics.get("per_language")
    if not isinstance(per_language, dict):
        _fail("Classifier manifest metrics are missing or malformed")
    parsed_per_language: dict[str, LanguageRecall] = {}
    for lang, payload in per_language.items():
        if not isinstance(payload, dict) or not _is_probability(payload.get("recall")):
            _fail("Classifier manifest metrics are missing or malformed")
        parsed_per_language[str(lang)] = LanguageRecall(recall=float(payload["recall"]))

    release_quality = obj.get("release_quality")
    if not isinstance(release_quality, bool):
        _fail("Classifier manifest release_quality must be a boolean")

    gate_failures = obj.get("gate_failures")
    if not isinstance(gate_failures, list) or not all(
        isinstance(item, str) for item in gate_failures
    ):
        _fail("Classifier manifest gate_failures must be an array of strings")
    if not release_quality and len(gate_failures) == 0:
        _fail(
            "Classifier manifest release_quality is false but gate_failures is empty; "
            "a non-release artifact must record why it failed release gates"
        )

    assert isinstance(attack_threshold, (int, float)) and not isinstance(attack_threshold, bool)
    assert isinstance(schema_version, int)
    assert isinstance(artifact_version, str)
    assert isinstance(model_sha256, str)
    assert isinstance(model_size_bytes, int)
    assert isinstance(normalization_version, str)
    assert isinstance(window_size_bytes, int)
    assert isinstance(window_stride_bytes, int)
    assert isinstance(corpus_revision, str)
    assert isinstance(q_format, str)
    assert isinstance(q_method, str)
    assert isinstance(metrics, dict)
    assert isinstance(release_quality, bool)
    assert isinstance(gate_failures, list)

    return ClassifierManifest(
        attack_threshold=float(attack_threshold),
        thresholds=parsed_thresholds,
        schema_version=schema_version,
        artifact_version=artifact_version,
        model_sha256=model_sha256,
        model_size_bytes=model_size_bytes,
        labels=list(CLASSIFIER_LABELS),
        normalization_version=normalization_version,
        window_size_bytes=window_size_bytes,
        window_stride_bytes=window_stride_bytes,
        corpus_revision=corpus_revision,
        quantization=Quantization(format=q_format, method=q_method),
        metrics=Metrics(
            macro_f1=float(metrics["macro_f1"]),
            macro_recall=float(metrics["macro_recall"]),
            benign_false_positive_rate=float(metrics["benign_false_positive_rate"]),
            attack_precision=float(metrics["attack_precision"]),
            attack_recall=float(metrics["attack_recall"]),
            attack_f1=float(metrics["attack_f1"]),
            per_language=parsed_per_language,
        ),
        release_quality=release_quality,
        gate_failures=list(gate_failures),
    )


def load_embedded_manifest_json() -> str:
    return (
        files("prompt_chainmail.shared.classifier")
        .joinpath("manifest.json")
        .read_text(encoding="utf-8")
    )


EMBEDDED_MANIFEST_JSON = load_embedded_manifest_json()
CLASSIFIER_MANIFEST = validate_manifest(json.loads(EMBEDDED_MANIFEST_JSON))
