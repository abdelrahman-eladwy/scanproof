#!/usr/bin/env sh
# Run the unit suite (adversarial decision matrix included) against an INSTALLED ScanProof:
# the built wheel (ci.yml package job) or the Docker image (docker job), never src/.
#
# Usage: scripts/test_installed.sh <python> <repo checkout>
#   <python> must have scanproof installed (with the attestations extra) plus pytest and respx.
set -eu
PY="$1"
REPO="$2"
WORK="$(mktemp -d)"
# The suite reads its fixtures, the example policies and pyproject (version check); no src/.
cp -R "$REPO/tests" "$REPO/examples" "$REPO/pyproject.toml" "$WORK/"
# CI-only scripts exercised by their own tests; never copy src/.
mkdir -p "$WORK/scripts"
cp "$REPO/scripts/ci_baseline.py" "$REPO/scripts/benchmark_verify_pipeline.py" \
  "$REPO/scripts/export_schemas.py" "$WORK/scripts/"
cp -R "$REPO/schemas" "$WORK/"
cd "$WORK"
"$PY" -c 'import scanproof, sys; print("testing installed scanproof", scanproof.__version__, "at", scanproof.__file__)'
SCANPROOF_TEST_INSTALLED=1 "$PY" -m pytest -q -p no:cacheprovider -rs tests
