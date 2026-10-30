#!/usr/bin/env bash
# Regenerate the hash-locked requirements. Needs uv (https://docs.astral.sh/uv/).
#   requirements/relock.sh
#
# build.txt  : the build backend (hatchling), installed first so nothing is built with an unpinned backend
# runtime.txt: what the image installs;  dev.txt: runtime + test/lint tools (CI);  tools.txt: pip-audit and bandit (CI)
# Every file is --require-hashes clean. Install order is in the Dockerfile and the workflow.
set -euo pipefail
cd "$(dirname "$0")/.."
c="uv pip compile --universal --python-version 3.11 --generate-hashes --no-header --quiet"
$c requirements/build.in -o requirements/build.txt
$c requirements/tools.in -o requirements/tools.txt
$c pyproject.toml -o requirements/runtime.txt
$c pyproject.toml --extra dev -o requirements/dev.txt
