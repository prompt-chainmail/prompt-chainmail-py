#!/usr/bin/env python3
"""Fetch the pinned classifier model and vendor it into the Python package.

Source resolution order:
  1. MODELS_REPO env / --models-repo (local checkout)
  2. Sibling ../prompt-chainmail-models
  3. GitHub raw URLs for prompt-chainmail/prompt-chainmail-models

Copies classifier.onnx + manifest.json + normalization_vectors.json into
src/prompt_chainmail/shared/classifier/.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import urllib.error
import urllib.request
from hashlib import sha256
from pathlib import Path

GITHUB_OWNER_REPO = "prompt-chainmail/prompt-chainmail-models"
GITHUB_BRANCH = "main"
MODEL_FILENAME_BY_FORMAT = {
    "INT8": "classifier.int8.onnx",
    "FLOAT32": "classifier.onnx",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_pin(pin_path: Path) -> dict[str, str]:
    return json.loads(pin_path.read_text(encoding="utf-8"))


def _sha256_hex(data: bytes) -> str:
    return sha256(data).hexdigest()


def _read_local_or_remote(
    version_dir: Path | None,
    filename: str,
    version: str,
    vendored_fallback: Path | None = None,
) -> tuple[bytes, str]:
    if version_dir is not None:
        local_path = version_dir / filename
        if local_path.is_file():
            return local_path.read_bytes(), f"local:{local_path}"

    url = (
        f"https://raw.githubusercontent.com/{GITHUB_OWNER_REPO}/{GITHUB_BRANCH}/"
        f"models/{version}/{filename}"
    )
    fetch_status = "unknown error"
    try:
        with urllib.request.urlopen(url) as response:  # noqa: S310 - pinned public GitHub raw
            return response.read(), f"github:{url}"
    except urllib.error.HTTPError as exc:
        fetch_status = f"HTTP {exc.code}"
    except urllib.error.URLError as exc:
        fetch_status = str(exc.reason)
    except OSError as exc:
        fetch_status = str(exc)

    if vendored_fallback is not None and vendored_fallback.is_file():
        print(
            f"Could not fetch {filename} ({fetch_status}); "
            f"using already-vendored {vendored_fallback}",
            file=sys.stderr,
        )
        return vendored_fallback.read_bytes(), f"vendored:{vendored_fallback}"

    raise SystemExit(
        f"Failed to fetch {filename} for model_version={version}: {fetch_status} ({url}). "
        "Clone prompt-chainmail-models as a sibling, pass --models-repo, or vendor files "
        "under src/prompt_chainmail/shared/classifier/."
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch the pinned ONNX classifier and vendor it into the Python package."
    )
    parser.add_argument("--models-repo", default=os.environ.get("MODELS_REPO"))
    parser.add_argument("--model-version", default=None)
    args = parser.parse_args()

    repo_root = _repo_root()
    pin_path = repo_root / "classifier-model-version.json"
    pin = _load_pin(pin_path)
    version = args.model_version or pin.get("model_version")
    if not version:
        raise SystemExit("No model_version in classifier-model-version.json or --model-version")

    sibling_default = repo_root.parent / "prompt-chainmail-models"
    models_repo = Path(args.models_repo) if args.models_repo else sibling_default
    version_dir = models_repo / "models" / version
    using_local = version_dir.is_dir()

    if using_local:
        print(f"Using local models repo: {version_dir}")
        local_dir: Path | None = version_dir
    else:
        print(
            f"Local models folder missing ({version_dir}); "
            f"will try GitHub raw for {GITHUB_OWNER_REPO}@{GITHUB_BRANCH}"
        )
        local_dir = None

    classifier_dir = repo_root / "src" / "prompt_chainmail" / "shared" / "classifier"
    classifier_dir.mkdir(parents=True, exist_ok=True)

    vendored_manifest = classifier_dir / "manifest.json"
    vendored_vectors = classifier_dir / "normalization_vectors.json"
    vendored_onnx = classifier_dir / "classifier.onnx"

    manifest_bytes, _ = _read_local_or_remote(
        local_dir, "manifest.json", version, vendored_manifest
    )
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    quantization_format = (manifest.get("quantization") or {}).get("format")
    model_filename = MODEL_FILENAME_BY_FORMAT.get(quantization_format)
    if model_filename is None:
        raise SystemExit(
            f"Unknown manifest quantization.format: {quantization_format}. "
            f"Expected one of {', '.join(MODEL_FILENAME_BY_FORMAT)}."
        )
    if not isinstance(manifest.get("attack_threshold"), (int, float)):
        raise SystemExit(
            "Manifest is missing attack_threshold. Expected dual-head export contract."
        )

    try:
        model_bytes, _ = _read_local_or_remote(local_dir, model_filename, version, None)
    except SystemExit:
        if vendored_onnx.is_file():
            print(
                f"Could not fetch {model_filename}; reusing vendored {vendored_onnx}",
                file=sys.stderr,
            )
            model_bytes = vendored_onnx.read_bytes()
        else:
            raise

    computed = _sha256_hex(model_bytes)
    expected = manifest.get("model_sha256")
    if computed != expected:
        raise SystemExit(f"Model checksum mismatch: manifest says {expected}, computed {computed}.")

    vectors_bytes, _ = _read_local_or_remote(
        local_dir, "normalization_vectors.json", version, vendored_vectors
    )

    dest_models = repo_root / "models" / version
    dest_models.mkdir(parents=True, exist_ok=True)
    (dest_models / "manifest.json").write_bytes(manifest_bytes)
    (dest_models / "normalization_vectors.json").write_bytes(vectors_bytes)
    (dest_models / model_filename).write_bytes(model_bytes)

    shutil.copyfile(dest_models / "manifest.json", classifier_dir / "manifest.json")
    shutil.copyfile(
        dest_models / "normalization_vectors.json",
        classifier_dir / "normalization_vectors.json",
    )
    shutil.copyfile(dest_models / model_filename, classifier_dir / "classifier.onnx")

    if args.model_version and args.model_version != pin.get("model_version"):
        pin["model_version"] = args.model_version
        pin_path.write_text(json.dumps(pin, indent=2) + "\n", encoding="utf-8")

    print("Fetched classifier model for Python runtime:")
    print(f"  model_version: {version}")
    print(f"  filename: {model_filename}")
    print(f"  quantization.format: {quantization_format}")
    print(f"  model bytes: {len(model_bytes)}")
    print(f"  sha256: {computed}")
    print(f"  attack_threshold: {manifest['attack_threshold']}")
    print(f"  embedded weights: {classifier_dir / 'classifier.onnx'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
