#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
NEW_DIR="$ROOT_DIR/new"

CONFIG="$NEW_DIR/Config/algorithms.json"

usage() {
  cat <<'EOF'
Usage:
  new/build_oneclick.sh [options]

Options:
  --config <path>      Config file path (default: new/Config/algorithms.json)
  --no-test            Accepted for compatibility; no-op in this public repo
  --alg <name>         Accepted for compatibility; ignored
  --class <klass>      Accepted for compatibility; ignored
  --provider <name>    Accepted for compatibility; ignored
  --build-dir <dir>    Accepted for compatibility; ignored
  -h, --help           Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG="$2"
      shift 2
      ;;
    --no-test)
      shift
      ;;
    --alg|--class|--provider|--build-dir)
      echo "[WARN] ignored option in public example repo: $1 $2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

python3 "$NEW_DIR/scripts/build_new_provider.py" \
  --config "$CONFIG" \
  --out-dir "$NEW_DIR/output"

SUMMARY_JSON="$NEW_DIR/output/last_build.json"
if [[ ! -f "$SUMMARY_JSON" ]]; then
  echo "[FAIL] missing $SUMMARY_JSON" >&2
  exit 2
fi

PROVIDER_SO="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1],"r",encoding="utf-8"))["provider_so"])' "$SUMMARY_JSON")"
PROVIDER_NAME="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1],"r",encoding="utf-8"))["provider"])' "$SUMMARY_JSON")"
PATCH_CONF="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1],"r",encoding="utf-8"))["patch_conf"])' "$SUMMARY_JSON")"
ALGORITHM_LIST="$(python3 -c 'import json,sys;data=json.load(open(sys.argv[1],"r",encoding="utf-8"));print(", ".join(x["name"] for x in data.get("algorithms", [])))' "$SUMMARY_JSON")"
INSTALL_SH="$NEW_DIR/output/install.sh"

cat <<MSG
[DONE] provider .so: $PROVIDER_SO
[DONE] patch conf: $PATCH_CONF
[DONE] install script: $INSTALL_SH
[DONE] summary: $SUMMARY_JSON
[INFO] algorithms: $ALGORITHM_LIST
[INFO] runtime libraries are prebuilt under $ROOT_DIR/runtime/lib
[INFO] this public repo only preserves the usage example, real algorithm integration sources, and ready-to-use artifacts
MSG
