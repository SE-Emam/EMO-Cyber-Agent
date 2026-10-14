# syntax=docker/dockerfile:1

ARG PYTHON_IMAGE=python:3.12-slim-bookworm

FROM ${PYTHON_IMAGE} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# The runtime drops all Linux capabilities and runs as an unprivileged user.
RUN groupadd --system --gid 10001 emo \
    && useradd --system --uid 10001 --gid 10001 --create-home --home-dir /home/emo emo

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY docs/schemas ./docs/schemas
COPY docs/policies ./docs/policies
COPY templates ./templates

RUN python -m pip install . \
    && chown -R emo:emo /app

USER emo

ENTRYPOINT ["cyber-agent"]
CMD ["--help"]


FROM runtime AS test

USER root
COPY tests ./tests
COPY scripts ./scripts
RUN python -m pip install ".[all]" \
    && chown -R emo:emo /app

USER emo

# The test target runs the repository gate directly instead of the runtime CLI.
ENTRYPOINT []
CMD ["sh", "-c", "ruff check src tests scripts && mypy src && pytest tests/unit -q --tb=short -p no:cacheprovider && python scripts/validate_schemas.py"]
