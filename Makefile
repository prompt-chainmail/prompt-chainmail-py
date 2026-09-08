.PHONY: fetch-classifier build test lint format typecheck audit

fetch-classifier:
	@uv run python scripts/fetch_classifier_model.py

build:
	uv build

test:
	uv run pytest

lint:
	uv run ruff check .

format:
	uv run ruff format .

typecheck:
	uv run ty check

audit:
	uv export --frozen --no-dev --no-hashes --no-emit-project --extra http --extra sentry -o /tmp/runtime-reqs.txt
	uv run pip-audit -r /tmp/runtime-reqs.txt --disable-pip --no-deps --strict
