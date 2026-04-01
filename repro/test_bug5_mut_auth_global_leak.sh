#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
cargo test -p spdmlib-test --features mandatory-mut-auth --test specula_bug_repros repro_mut_auth_done_leaks_across_sessions -- --nocapture
