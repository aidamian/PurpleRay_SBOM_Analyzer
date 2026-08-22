#!/usr/bin/env bash
# Copyright (c) 2026 Andrei Ionut Damian.
# Licensed under the Apache License, Version 2.0; see ../LICENSE.

set -euo pipefail

if [[ $# -ne 0 ]]; then
  echo 'usage: prepare-version-commit.sh' >&2
  exit 2
fi

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

section() {
  printf '\n==> %s\n' "$1"
}

section 'Synchronizing tracked version fallbacks from VERSION'
scripts/write-version.sh
scripts/check-version.sh

section 'Checking staged and unstaged diffs for whitespace errors'
git diff --check
git diff --cached --check

section 'Running the non-UI test suite'
scripts/run-tests.sh

section 'Building the Linux GTK2 Release binary'
scripts/build-linux.sh

section 'Commit candidate status'
git status --short --branch

printf '\nUnstaged diff summary:\n'
if git diff --quiet; then
  echo '  (none)'
else
  git diff --stat
fi

printf '\nStaged diff summary:\n'
if git diff --cached --quiet; then
  echo '  (none)'
else
  git diff --cached --stat
fi

printf '\nAll local preparation gates passed for VERSION %s.\n' "$(<VERSION)"
echo 'Nothing was staged, committed, tagged, or pushed; review the status and diffs above.'
