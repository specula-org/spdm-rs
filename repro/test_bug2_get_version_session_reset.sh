#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
cargo test -p spdmlib-test --test specula_bug_repros repro_get_version_resets_live_session -- --nocapture
