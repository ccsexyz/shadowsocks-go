#!/bin/bash
# bench_compare.sh — Benchmark multiple shadowsocks-go versions and generate HTML report.
#
# Usage:
#   ./scripts/bench_compare.sh HEAD
#   ./scripts/bench_compare.sh 36ce5e5 1b065d0 HEAD
#   ./scripts/bench_compare.sh --conns 10,100 --duration 10s HEAD
#   ./scripts/bench_compare.sh --refresh HEAD          # force re-run, update cache
#   ./scripts/bench_compare.sh --nocache HEAD          # run without cache
#
# Output: $TMPDIR/bench_report.html (HTML) and text summary to stdout.
#
# Cache: $TMPDIR/cache/$commit/$method_$payload_$conns.json
#   --nocache   ignore cache, don't write
#   --refresh   ignore cache read, but write results
#   (default)   use cache hits, write misses

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJ_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
TMPDIR="${CC_TMP:-/tmp/ss-go}"
mkdir -p "$TMPDIR"

# ---- Defaults ----
METHODS="aes-256-gcm,2022-blake3-aes-256-gcm"
PAYLOADS="1024,16384,65536"
CONNS="10,100"
DURATION="8s"
WARMUP="3s"
REPEAT=2
JOBS=1
OUT_FILE=""
COMMITS=()
CACHE_MODE="rw"   # rw | none | refresh

usage() {
  echo "usage: $0 [options] <commit> [commit2...]"
  echo "options:"
  echo "  --methods    comma-separated (default: $METHODS)"
  echo "  --payloads   comma-separated (default: $PAYLOADS)"
  echo "  --conns      comma-separated (default: $CONNS)"
  echo "  --duration   e.g. 8s, 10s (default: $DURATION)"
  echo "  --warmup     e.g. 3s (default: $WARMUP)"
  echo "  --repeat     int (default: $REPEAT)"
  echo "  --jobs       max concurrent scenarios (default: $JOBS)"
  echo "  --tmpdir     temp directory (default: $TMPDIR)"
  echo "  -o           output HTML path (default: \$TMPDIR/bench_report.html)"
  echo "  --nocache    ignore cache entirely"
  echo "  --refresh    ignore cached results, but write new ones"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --methods)  METHODS="$2"; shift 2 ;;
    --payloads) PAYLOADS="$2"; shift 2 ;;
    --conns)    CONNS="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --warmup)   WARMUP="$2"; shift 2 ;;
    --repeat)   REPEAT="$2"; shift 2 ;;
    --jobs)     JOBS="$2"; shift 2 ;;
    --tmpdir)   TMPDIR="$2"; mkdir -p "$TMPDIR"; shift 2 ;;
    --nocache)  CACHE_MODE="none"; shift ;;
    --refresh)  CACHE_MODE="refresh"; shift ;;
    -o)         OUT_FILE="$2"; shift 2 ;;
    -h|--help)  usage ;;
    *)          COMMITS+=("$1"); shift ;;
  esac
done

if [[ ${#COMMITS[@]} -lt 1 ]]; then
  usage
fi

# ---- Guard against dirty working tree ----
if ! git diff-index --quiet HEAD -- 2>/dev/null; then
  echo "ERROR: working tree has uncommitted changes. Commit or stash them first."
  exit 1
fi

OUT_FILE="${OUT_FILE:-$TMPDIR/bench_report.html}"
CACHE_DIR="$TMPDIR/cache"

# ---- Build valid password map ----
gen_passwords() {
  cat << 'PWEOF'
{
  "aes-128-gcm": "bench-bench-128!!",
  "aes-192-gcm": "bench-bench-192!!!bench-",
  "aes-256-gcm": "bench-bench-256!!!bench-bench-!!",
  "chacha20-ietf-poly1305": "bench-bench-256!!!bench-bench-!!",
  "chacha20-poly1305": "bench-bench-256!!!bench-bench-!!",
  "chacha20poly1305": "bench-bench-256!!!bench-bench-!!",
  "plain": "",
  "2022-blake3-aes-128-gcm": "AAAAAAAAAAAAAAAAAAAAAA==",
  "2022-blake3-aes-256-gcm": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "2022-blake3-chacha20-poly1305": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
}
PWEOF
}

echo "=== config ==="
echo "  methods=$METHODS  payloads=$PAYLOADS  conns=$CONNS  dur=$DURATION  warm=$WARMUP  repeat=$REPEAT  cache=$CACHE_MODE  jobs=$JOBS"

# ---- Build full JSON config (used once per scenario) ----
build_config() {
  local method="$1" payload="$2" conns="$3"
  python3 -c "
import json
cfg = {
    'methods': ['$method'],
    'payloads': [$payload],
    'concurrencies': [$conns],
    'duration': '$DURATION',
    'warmup': '$WARMUP',
    'repeat': int('$REPEAT'),
    'latency': True,
	    'jobs': int('$JOBS'),
}
pw_json = '''$(gen_passwords)'''
cfg['passwords'] = json.loads(pw_json)
print(json.dumps(cfg))
"
}

declare -a ALL_PIDS=()

# ---- Build bench tool ----
echo ""
echo "=== building bench tool ==="
cd "$PROJ_DIR"
go build -o "$TMPDIR/bench" ./cmd/bench/
echo "  bench: $TMPDIR/bench"

# ---- Benchmark each commit ----
declare -a RESULT_FILES=()
declare -a LABELS=()
declare -a SS_BINS=()
ORIG_BRANCH=$(git branch --show-current 2>/dev/null || echo "HEAD")
cleanup() {
  for pid in "${ALL_PIDS[@]:-}"; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  done
  git checkout --quiet "$ORIG_BRANCH" 2>/dev/null || true
}
trap cleanup EXIT

IFS=',' read -ra MARR <<< "$METHODS"
IFS=',' read -ra PARR <<< "$PAYLOADS"
IFS=',' read -ra CARR <<< "$CONNS"

# ---- Phase 1: build binaries for all commits ----
for commit in "${COMMITS[@]}"; do
  echo ""
  echo "=== building binary for: $commit ==="
  git checkout --quiet "$commit"
  SHORT_HASH=$(git rev-parse --short HEAD)
  LABELS+=("$SHORT_HASH")

  SS_BIN="$TMPDIR/ss-$SHORT_HASH"
  SS_BINS+=("$SS_BIN")
  if [[ -f "$SS_BIN" ]]; then
    echo "  binary cached: $SS_BIN"
  else
    go build -o "$SS_BIN" ./cmd/shadowsocks/
    echo "  built: $(ls -lh "$SS_BIN" | awk '{print $5}')"
  fi
done

# Return to original branch immediately after building
git checkout --quiet "$ORIG_BRANCH"

# ---- Phase 2: run benchmarks using cached binaries ----
idx=0
for commit in "${COMMITS[@]}"; do
  SHORT_HASH="${LABELS[$idx]}"
  SS_BIN="${SS_BINS[$idx]}"
  idx=$((idx + 1))

  echo ""
  echo "=== commit: $commit ($SHORT_HASH) ==="

  COMMIT_CACHE="$CACHE_DIR/$SHORT_HASH"
  mkdir -p "$COMMIT_CACHE"
  COMMIT_RESULT="$TMPDIR/bench_${SHORT_HASH}.json"
  CACHED=0
  FRESH=0
  declare -a PARTS=()

  for method in "${MARR[@]}"; do
    for payload in "${PARR[@]}"; do
      for conns in "${CARR[@]}"; do
        safe_method="${method//\//_}"
        CACHE_FILE="$COMMIT_CACHE/${safe_method}_${payload}_${conns}.json"

        if [[ "$CACHE_MODE" != "none" && "$CACHE_MODE" != "refresh" && -f "$CACHE_FILE" ]]; then
          echo "  [cached] $method p=$payload c=$conns"
          PARTS+=("$CACHE_FILE")
          CACHED=$((CACHED + 1))
          continue
        fi

        echo "  [run] $method p=$payload c=$conns"
        CFG_FILE="$TMPDIR/bench_cfg_$$.json"
        build_config "$method" "$payload" "$conns" > "$CFG_FILE"
        "$TMPDIR/bench" run "$SS_BIN" "$CFG_FILE" 2>/dev/null > "$CACHE_FILE" || true
        rm -f "$CFG_FILE"
        PARTS+=("$CACHE_FILE")
        FRESH=$((FRESH + 1))
      done
    done
  done

  # Merge parts into one result array
  python3 -c "
import json, os
results = []
for p in '''$(printf '%s\n' "${PARTS[@]}")'''.strip().split('\n'):
    if p and os.path.exists(p):
        with open(p) as f:
            results.extend(json.load(f))
print(json.dumps(results))
" > "$COMMIT_RESULT"

  RESULT_FILES+=("$COMMIT_RESULT")
  echo "  total=$(($CACHED + $FRESH)) cached=$CACHED fresh=$FRESH"
done

# ---- Generate report ----
echo ""
echo "=== generating report ==="

COMPARE_ARGS=(--html -o "$OUT_FILE")
for i in "${!COMMITS[@]}"; do
  COMPARE_ARGS+=(--label "${LABELS[$i]}")
done
for f in "${RESULT_FILES[@]}"; do
  COMPARE_ARGS+=("$f")
done
"$TMPDIR/bench" compare "${COMPARE_ARGS[@]}" 2>&1

echo ""
echo "=== report: $OUT_FILE ==="
ls -lh "$OUT_FILE"
echo ""
echo "Text summary:"
TEXT_ARGS=()
for i in "${!COMMITS[@]}"; do
  TEXT_ARGS+=(--label "${LABELS[$i]}")
done
for f in "${RESULT_FILES[@]}"; do
  TEXT_ARGS+=("$f")
done
"$TMPDIR/bench" compare "${TEXT_ARGS[@]}" 2>&1
