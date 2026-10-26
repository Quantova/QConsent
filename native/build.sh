#!/usr/bin/env bash
# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
RUSTUP_HOME_DIR="${RUSTUP_HOME:-$HOME/.rustup}"
export RUSTFLAGS="--remap-path-prefix=$HERE=/qconsent --remap-path-prefix=$CARGO_HOME_DIR=/cargo --remap-path-prefix=$RUSTUP_HOME_DIR=/rustup"
cd "$HERE"
wasm-pack build --release --target nodejs --out-dir ../wasm --out-name qconsent_native --no-pack -- --locked
rm -f ../wasm/.gitignore
