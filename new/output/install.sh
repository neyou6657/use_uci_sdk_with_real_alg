#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEST_DIR="${1:-$SCRIPT_DIR/install}"

INCLUDE_SRC="$REPO_ROOT/include/uci"
LIBUCI_SRC="$REPO_ROOT/runtime/lib/libuci.so"
LIBMTOKEN_SRC="$REPO_ROOT/runtime/lib/libmtoken_gm3000.so"
PROVIDER_SO_SRC="$SCRIPT_DIR/providers/pqvariantprovider.so"
PATCH_CONF_SRC="$SCRIPT_DIR/pqvariantprovider.patch.conf"
SUMMARY_JSON_SRC="$SCRIPT_DIR/last_build.json"
PROVIDER_NAME="pqvariantprovider"
ALGORITHM_LIST="sntrup761, cross-rsdp-128-small"

mkdir -p "$DEST_DIR/include" "$DEST_DIR/lib/ossl-modules" "$DEST_DIR/etc/uci"

for required in "$INCLUDE_SRC" "$LIBUCI_SRC" "$LIBMTOKEN_SRC" "$PATCH_CONF_SRC" "$SUMMARY_JSON_SRC"; do
  if [[ ! -e "$required" ]]; then
    echo "[FAIL] missing artifact: $required" >&2
    exit 2
  fi
done

cp -R "$INCLUDE_SRC" "$DEST_DIR/include/"
cp "$LIBUCI_SRC" "$DEST_DIR/lib/"
cp "$LIBMTOKEN_SRC" "$DEST_DIR/lib/"
cp "$PATCH_CONF_SRC" "$DEST_DIR/etc/uci/"
cp "$SUMMARY_JSON_SRC" "$DEST_DIR/etc/uci/"

if [[ ! -f "$PROVIDER_SO_SRC" ]]; then
  echo "[FAIL] missing provider .so: $PROVIDER_SO_SRC" >&2
  exit 2
fi
cp "$PROVIDER_SO_SRC" "$DEST_DIR/lib/ossl-modules/"

cat <<MSG
[PASS] install completed
[INFO] provider: $PROVIDER_NAME
[INFO] algorithms: $ALGORITHM_LIST
[INFO] include: $DEST_DIR/include/uci
[INFO] libuci: $DEST_DIR/lib/libuci.so
[INFO] compat-lib: $DEST_DIR/lib/libmtoken_gm3000.so
[INFO] provider-so: $DEST_DIR/lib/ossl-modules/pqvariantprovider.so
[INFO] patch-conf: $DEST_DIR/etc/uci/pqvariantprovider.patch.conf

Export before running your app:
  export LD_LIBRARY_PATH="$DEST_DIR/lib:${LD_LIBRARY_PATH:-}"
  export OPENSSL_MODULES="$DEST_DIR/lib/ossl-modules"
  export SDFR_PATCH_FILE="$DEST_DIR/etc/uci/pqvariantprovider.patch.conf"
MSG
