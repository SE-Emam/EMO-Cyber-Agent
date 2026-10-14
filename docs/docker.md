# Docker operation

EMO-Cyber provides a reproducible Docker runtime and a separate test target.
The image is built from Python 3.12 slim Bookworm, installs the package from
the checked-out source, and runs as the unprivileged `emo` user. Runtime
containers drop all Linux capabilities, enable `no-new-privileges`, mount the
root filesystem read-only, and run without network access by default.

## Build and run

```bash
make docker-build
make docker-run
```

`docker-build` is the only step that needs registry or package-index access
when the base image and Python wheels are not already cached. `docker-run`
uses the locally built image and the `doctor` command with the network
disabled.

## Run the project checks

```bash
make docker-test
```

The test target contains the development dependencies and runs the daily
quality gate: Ruff, mypy, the unit suite, and schema validation. Release
qualification remains a separate step because it needs freshly built
artifacts, release metadata, and the installation tools used by
`tests/release/`. The test container has no network access at runtime;
dependencies are installed during the image build.

When lint debt needs to be isolated from runtime and unit behavior, run:

```bash
make docker-unit
```

This runs mypy, all unit tests, and schema validation without the repository
wide Ruff gate.

## Supply-chain and scope rules

- Build from the repository root so the Dockerfile receives only this project
  context; `.dockerignore` excludes Git metadata, local virtual environments,
  reports, and build output.
- Do not mount the Docker socket into the container.
- Use a reviewed base-image digest for release builds. The default tag is
  intentionally convenient for local development and must be pinned by the
  release pipeline before publishing an image.
- Docker support is an execution and verification surface. It does not grant
  EMO-Cyber write access, shell execution, or network capabilities.
