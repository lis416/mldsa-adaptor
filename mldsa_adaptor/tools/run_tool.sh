#!/bin/sh
# Usage: tools/run_tool.sh reject_breakdown | naive_mask
# Copies the crate to a temporary directory, applies tools/<name>/patch.py there, and runs the tool.
# The main tree is never modified.
set -e
NAME="$1"; ROOT="$(cd "$(dirname "$0")/.." && pwd)"; TMP="$(mktemp -d)"
cp -r "$ROOT/Cargo.toml" "$ROOT/Cargo.lock" "$ROOT/src" "$ROOT/vendor" "$TMP/"
python3 "$ROOT/tools/$NAME/patch.py" "$TMP"
cp "$ROOT/tools/$NAME/"*.rs "$TMP/src/bin/"
BIN=$(basename "$ROOT/tools/$NAME/"*.rs .rs)
(cd "$TMP" && cargo build --release -q --bin "$BIN" && "./target/release/$BIN")
rm -rf "$TMP"
