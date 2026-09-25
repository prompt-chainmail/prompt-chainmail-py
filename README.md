# Prompt Chainmail

<div align="center">
  <img src="src/logo.png" alt="Prompt Chainmail Logo" width="200" height="234">
</div>

<br/>

**Security middleware for AI prompt protection**

Security middleware that shields AI applications from prompt injection, jailbreaking, role confusion, tool hijacking attempts and obfuscated attacks through composable defense layers.

Also available in TypeScript ([`prompt-chainmail-ts`](https://github.com/prompt-chainmail/prompt-chainmail-ts)) and Rust ([`prompt-chainmail-rs`](https://github.com/prompt-chainmail/prompt-chainmail-rs)).

[![CI/CD Pipeline](https://github.com/prompt-chainmail/prompt-chainmail-py/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/prompt-chainmail/prompt-chainmail-py/actions/workflows/ci.yml)
[![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-blue.svg)](LICENSE.md)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![Security Audit](https://img.shields.io/badge/security-audited-green.svg)](https://github.com/prompt-chainmail/prompt-chainmail-py/actions/workflows/security.yml)
[![Beta](https://img.shields.io/badge/status-beta-orange.svg)](https://github.com/prompt-chainmail/prompt-chainmail-py)

The public API is **synchronous** (`protect` / `protect_bytes`) with a thin `protect_async()` wrapper that offloads to a thread. Method names use idiomatic Python `snake_case`; preset composition and flag strings match the TypeScript package.

## Features

- **Security** — Composable rivet system for layered defenses
- **Offline Classifier** — Portable ONNX classifier (no network calls, no API keys) backs `role_confusion()`, `instruction_hijacking()`, `tool_use_hijacking()`, and `side_channel()`
- **Minimal Dependencies** — `lingua-language-detector` for language detection and `onnxruntime` for local inference; no cloud embedding APIs
- **Python 3.12+** — Packaged with uv, typed (`py.typed`), hatchling wheel with embedded ONNX
- **Compliance Ready** — Flags, confidence, and metadata suitable for audit logging
- **Monitoring Integration** — Telemetry rivet with a console provider, optional Sentry extra, and a `TelemetryProvider` protocol

> The bundled ONNX classifier (pin `2026.09.25` from [`prompt-chainmail-models`](https://github.com/prompt-chainmail/prompt-chainmail-models); `release_quality: false`) is a 12-head model: macro_f1 ≈ 0.853, macro_recall ≈ 0.909, attack F1 ≈ 0.979, benign false-positive rate ≈ 1.25%. Language recall is at or above 0.80. The benign false-positive gate is still open.

## Install

```bash
uv add prompt-chainmail
# or
pip install prompt-chainmail
```

Optional extras:

```bash
uv add "prompt-chainmail[http]"     # httpx for Rivets.http_fetch
uv add "prompt-chainmail[sentry]"   # Sentry telemetry adapter
```

No model setup for consumers: the pinned ONNX weights ship in the wheel and are verified at load time. Works offline out of the box.

## Quick start

```python
from prompt_chainmail import Chainmails

chainmail = Chainmails.strict()
result = chainmail.protect(user_input)

if not result.success:
    print("Security violation:", result.context.flags)
else:
    print("Safe input:", result.context.sanitized)
```

Async (FastAPI / asyncio):

```python
result = await chainmail.protect_async(user_input)
```

### Presets

```python
Chainmails.basic()  # sanitize, patterns, role_confusion, delimiters, confidence 0.6
Chainmails.advanced()  # + hijacking families, injections, encoding, structure, rate_limit_filter
Chainmails.development()  # advanced + logger
Chainmails.strict()  # advanced with confidence 0.8 and rate_limit_filter(50, 60000)
```

### Custom chain

```python
from prompt_chainmail import PromptChainmail, Rivets

chainmail = (
    PromptChainmail()
    .forge(Rivets.sanitize())
    .forge(Rivets.pattern_detection())
    .forge(Rivets.confidence_filter(0.8))
)
result = chainmail.protect(user_input)
```

Detectors add flags and subtract leftover trust. They do not set `blocked`. `context.blocked` is set only by a forged filter: `confidence_filter` (trust gate) or `rate_limit_filter` (quota).

| Rivet | Role | Blocks |
| --- | --- | --- |
| `Rivets.sanitize()` | HTML removal, whitespace | no |
| `Rivets.pattern_detection()` | Common injection patterns | no |
| `Rivets.role_confusion()` | Role manipulation (classifier) | no |
| `Rivets.encoding_detection()` | Encoded payloads | no |
| `Rivets.structure_analysis()` | Structure anomalies | no |
| `Rivets.code_injection()` | Code execution attempts | no |
| `Rivets.sql_injection()` | SQL injection patterns | no |
| `Rivets.delimiter_confusion()` | Context-breaking delimiters | no |
| `Rivets.instruction_hijacking()` | Instruction override (classifier) | no |
| `Rivets.tool_use_hijacking()` | Indirect tool abuse (classifier) | no |
| `Rivets.side_channel()` | Unofficial side channels (classifier) | no |
| `Rivets.language_detection()` | Language detection | no |
| `Rivets.template_injection()` | Template syntax injection | no |
| `Rivets.confidence_filter()` | Trust gate on leftover confidence | yes |
| `Rivets.rate_limit_filter()` | Quota filter | yes |
| `Rivets.untrusted_wrapper()` | Security boundary tags | no |
| `Rivets.http_fetch()` | External HTTP (`http` extra) | no |
| `Rivets.condition()` | Custom predicates | no |
| `Rivets.logger()` | Request logging | no |
| `Rivets.telemetry()` | Monitoring | no |

## Development

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12+.

```bash
uv sync --group dev
make test
make lint
make typecheck
make audit
make fetch-classifier   # refresh embedded ONNX from the pinned model_version
```

PyPI publish is Actions → **Publish to PyPI** (`workflow_dispatch`) after a pending trusted publisher is registered on PyPI for workflow `publish-pypi.yml` and environment `pypi`.

Parity against TypeScript / Rust (same cases and line format):

```bash
uv run python examples/parity_compare.py
```

## License

Business Source License 1.1 — see [LICENSE.md](LICENSE.md). Free for non-production use; converts to Apache 2.0 on January 1, 2029 (same terms as the TypeScript package).
