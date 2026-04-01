#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="${1:-}"
OUT_DIR="${2:-$SCRIPT_DIR/build}"
CC_BIN="${CC:-cc}"
SRC="$SCRIPT_DIR/uciapi.c"
BIN="$OUT_DIR/uciapi"

usage() {
  cat <<'EOF'
Usage:
  cli/build.sh <install-prefix> [out-dir]

Example:
  cli/build.sh /tmp/pqvariant_pkg /tmp/pqvariant_cli
EOF
}

if [[ -z "$INSTALL_DIR" ]]; then
  usage >&2
  exit 2
fi

if [[ ! -f "$SRC" ]]; then
  echo "[FAIL] missing source: $SRC" >&2
  exit 2
fi

if [[ ! -d "$INSTALL_DIR/include/uci" ]]; then
  echo "[FAIL] missing headers: $INSTALL_DIR/include/uci" >&2
  exit 2
fi

if [[ ! -f "$INSTALL_DIR/lib/libuci.so" ]]; then
  echo "[FAIL] missing library: $INSTALL_DIR/lib/libuci.so" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"

"$CC_BIN" \
  -std=c11 \
  -Wall -Wextra \
  -I"$INSTALL_DIR/include" \
  "$SRC" \
  -L"$INSTALL_DIR/lib" \
  -Wl,-rpath,"$INSTALL_DIR/lib" \
  -luci \
  -o "$BIN"

cat <<MSG
[PASS] cli demo build completed
[INFO] binary: $BIN
[INFO] headers: $INSTALL_DIR/include/uci
[INFO] libuci: $INSTALL_DIR/lib/libuci.so
MSG
