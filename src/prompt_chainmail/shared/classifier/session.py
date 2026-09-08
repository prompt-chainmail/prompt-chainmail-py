from __future__ import annotations

import json
import os
import threading
from importlib.resources import files
from pathlib import Path

import onnxruntime as ort

from prompt_chainmail.shared.classifier.checksum import sha256_hex
from prompt_chainmail.shared.classifier.manifest import CLASSIFIER_MANIFEST
from prompt_chainmail.shared.classifier.types import ClassifierManifest

_MODEL_DIR_ENV = "PROMPT_CHAINMAIL_MODEL_DIR"
_PIN_FILENAME = "classifier-model-version.json"


class ClassifierError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class ClassifierSessionHandle:
    def __init__(self, session: ort.InferenceSession, manifest: ClassifierManifest) -> None:
        self.session = session
        self.manifest = manifest
        self._lock = threading.Lock()

    def run(self, feeds: dict[str, object]) -> dict[str, object]:
        with self._lock:
            output_names = [output.name for output in self.session.get_outputs()]
            values = self.session.run(output_names, feeds)
            return dict(zip(output_names, values, strict=True))


def _pin_payload() -> dict[str, object]:
    packaged = files("prompt_chainmail").joinpath(_PIN_FILENAME)
    if packaged.is_file():
        return json.loads(packaged.read_text(encoding="utf-8"))

    here = Path(__file__).resolve()
    candidates = [
        here.parents[4] / _PIN_FILENAME,
        here.parents[2] / _PIN_FILENAME,
        Path.cwd() / _PIN_FILENAME,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return json.loads(candidate.read_text(encoding="utf-8"))
    raise ClassifierError("pin_missing", "classifier-model-version.json was not found")


def pinned_model_version() -> str:
    payload = _pin_payload()
    version = payload.get("model_version")
    if isinstance(version, str) and version:
        return version
    raise ClassifierError("pin_missing", "classifier-model-version.json is missing model_version")


def resolve_model_dir() -> Path:
    env_dir = os.environ.get(_MODEL_DIR_ENV)
    if env_dir is not None:
        path = Path(env_dir)
        if path.is_dir():
            return path
        raise ClassifierError(
            "model_dir_missing",
            f"PROMPT_CHAINMAIL_MODEL_DIR is set but is not a directory: {path}",
        )
    raise ClassifierError(
        "model_dir_not_used",
        "No PROMPT_CHAINMAIL_MODEL_DIR set; using embedded classifier.onnx",
    )


def _model_filename(manifest: ClassifierManifest) -> str:
    if manifest.quantization.format == "INT8":
        return "classifier.int8.onnx"
    return "classifier.onnx"


def verify_model_bytes(data: bytes, manifest: ClassifierManifest, source: str) -> None:
    if len(data) != manifest.model_size_bytes:
        raise ClassifierError(
            "model_size_mismatch",
            (
                f"Classifier model size {len(data)} does not match "
                f"manifest {manifest.model_size_bytes} ({source})"
            ),
        )
    if sha256_hex(data) != manifest.model_sha256:
        raise ClassifierError(
            "checksum_mismatch",
            f"Classifier model checksum does not match the manifest ({source})",
        )


def embedded_model_bytes(manifest: ClassifierManifest) -> bytes:
    resource = files("prompt_chainmail.shared.classifier").joinpath("classifier.onnx")
    try:
        data = resource.read_bytes()
    except (FileNotFoundError, OSError) as exc:
        raise ClassifierError(
            "model_read_failed",
            f"Failed to read embedded classifier.onnx: {exc}",
        ) from exc
    verify_model_bytes(data, manifest, "embedded classifier.onnx")
    return data


def load_and_verify_model(directory: Path, manifest: ClassifierManifest) -> bytes:
    path = directory / _model_filename(manifest)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ClassifierError("model_read_failed", f"Failed to read {path}: {exc}") from exc
    verify_model_bytes(data, manifest, str(path))
    return data


def load_classifier_model_bytes(manifest: ClassifierManifest) -> bytes:
    if os.environ.get(_MODEL_DIR_ENV) is not None:
        return load_and_verify_model(resolve_model_dir(), manifest)
    return embedded_model_bytes(manifest)


def create_ort_session(model_bytes: bytes) -> ort.InferenceSession:
    try:
        return ort.InferenceSession(model_bytes, providers=["CPUExecutionProvider"])
    except Exception as exc:
        raise ClassifierError(
            "session_create_failed",
            f"Failed to create classifier inference session: {exc}",
        ) from exc


def create_classifier_session() -> ClassifierSessionHandle:
    manifest = CLASSIFIER_MANIFEST
    model_bytes = load_classifier_model_bytes(manifest)
    return ClassifierSessionHandle(create_ort_session(model_bytes), manifest)


_cached_session: ClassifierSessionHandle | ClassifierError | None = None
_cached_lock = threading.Lock()


def get_classifier_session() -> ClassifierSessionHandle:
    global _cached_session
    with _cached_lock:
        if _cached_session is None:
            try:
                _cached_session = create_classifier_session()
            except ClassifierError as exc:
                _cached_session = exc
        if isinstance(_cached_session, ClassifierError):
            raise ClassifierError(_cached_session.code, _cached_session.message)
        return _cached_session


def reset_classifier_session_for_tests() -> None:
    global _cached_session
    with _cached_lock:
        _cached_session = None
