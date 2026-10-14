.PHONY: install test lint typecheck format check audit-schema docker-build docker-run docker-test docker-unit

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

docker-build:
	docker compose build emo-cyber

docker-run:
	docker compose run --rm emo-cyber

docker-test:
	docker compose run --rm test

docker-unit:
	docker compose run --rm test sh -c 'mypy src && pytest tests/unit -q --tb=short -p no:cacheprovider && python scripts/validate_schemas.py'
