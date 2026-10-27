# Base image pinned by digest (Dependabot updates it). Same python:3.12-slim the fixtures were
# scanned from on 2026-10-26.
ARG PYTHON_IMAGE=python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704

FROM ${PYTHON_IMAGE} AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM ${PYTHON_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/abdelrahman-eladwy/scanproof" \
      org.opencontainers.image.description="ScanProof - Security Scan Assurance Engine" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 scanproof
COPY --from=build /dist/*.whl /tmp/
# With the attestations extra (sigstore-python), so `attestation:` policies work in the image.
RUN pip install --no-cache-dir "$(ls /tmp/*.whl)[attestations]" && rm /tmp/*.whl
USER 10001
WORKDIR /work
ENTRYPOINT ["scanproof"]
CMD ["--help"]
