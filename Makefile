.PHONY: install test lint typecheck format check audit-schema

install:
	python -m pip install -e '.[all]'

test:
	pytest

lint:
	ruff check src tests scripts

typecheck:
	mypy src

format:
	ruff format src tests scripts

check: lint typecheck test audit-schema

audit-schema:
	python scripts/validate_schemas.py
