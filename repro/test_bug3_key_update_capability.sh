#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
cargo test -p spdmlib-test --test specula_bug_repros repro_key_update_without_key_update_capability -- --nocapture
