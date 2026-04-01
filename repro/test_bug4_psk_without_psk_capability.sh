#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
cargo test -p spdmlib-test --test specula_bug_repros repro_psk_session_without_psk_capability -- --nocapture
