#!/bin/bash
# perf_compare.sh — Compare performance between old (6e8c36c) and new (HEAD)
# shadowsocks-go binaries using real load + pprof profiling.
#
# Test scenarios: TCP with aes-256-gcm and 2022-blake3-aes-256-gcm
# Each: 10s pprof CPU profile under 100-conn concurrent persistent load, 512B payload.
#
# Output: throughput numbers + CPU profile diff via 'go tool pprof -diff'.
#
# SAFETY: All processes are tracked by PID and killed individually.
# No pkill or pattern-based killing is used.

set -euo pipefail

BENCH_DIR=$(cd "$(dirname "$0")/.." && pwd)
WORKDIR=$(mktemp -d /tmp/perf_compare.XXXXXX)
declare -a ALL_PIDS=()

# ---- PID-safe cleanup ----

kill_pids() {
    for pid in "$@"; do
        kill -9 "$pid" 2>/dev/null || true
    done
}

wait_pids() {
    for pid in "$@"; do
        wait "$pid" 2>/dev/null || true
    done
}

cleanup_all() {
    if [ ${#ALL_PIDS[@]} -gt 0 ]; then
        kill_pids "${ALL_PIDS[@]}"
        wait_pids "${ALL_PIDS[@]}"
        ALL_PIDS=()
    fi
}

cleanup() {
    cleanup_all
    rm -rf "$WORKDIR" 2>/dev/null
}
trap cleanup EXIT

OLD_BIN="$WORKDIR/ss-old"
NEW_BIN="$WORKDIR/ss-new"
PLOAD_BIN="$WORKDIR/pload"

echo "=== shadowsocks-go Performance Comparison ==="
echo "Workdir: $WORKDIR"
echo ""

# ---- Step 1: Build ----

echo "--- Building ---"

cd "$BENCH_DIR"
go build -o "$NEW_BIN" ./cmd/shadowsocks/ && echo "  new: $(ls -lh "$NEW_BIN" | awk '{print $5}')"
cp /tmp/pload "$PLOAD_BIN" 2>/dev/null || go build -o "$PLOAD_BIN" ./cmd/pload/
echo "  pload: $(ls -lh "$PLOAD_BIN" | awk '{print $5}')"

OLD_TREE=$(mktemp -d /tmp/perf_old_tree.XXXXXX)
git worktree add --detach "$OLD_TREE" 6e8c36c 2>&1
cd "$OLD_TREE"
go build -o "$OLD_BIN" ./cmd/shadowsocks/ && echo "  old: $(ls -lh "$OLD_BIN" | awk '{print $5}')"
cd "$BENCH_DIR"
trap "cleanup; git worktree remove --force '$OLD_TREE' 2>/dev/null" EXIT

echo ""

# ---- Step 2: Helpers ----

free_port() {
    python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()"
}

# ---- Step 3: Run scenario ----

run_scenario() {
    local label="$1"    # old or new
    local bin="$2"
    local method="$3"
    local password="$4"

    echo "=== Scenario: $label $method ==="
    local -a pids=()

    # Start TCP echo server
    local echo_port=$(free_port)
    python3 -c "
import socket, threading, sys, signal
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $echo_port))
s.listen(5)
def handle(c):
    try:
        while True:
            data = c.recv(4096)
            if not data: break
            c.sendall(data)
    except: pass
    c.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
" &
    local echo_pid=$!
    pids+=($echo_pid)
    sleep 0.3
    echo "  echo: 127.0.0.1:$echo_port (pid $echo_pid)"

    # Free ports
    local ss_port=$(free_port)
    local local_port=$(free_port)
    local pp_port=$(free_port)

    # Start SS server
    "$bin" -type server \
        -l "127.0.0.1:$ss_port" \
        -m "$method" -p "$password" \
        -pprof "127.0.0.1:$pp_port" \
        -verbose \
        > "$WORKDIR/${label}_${method}_srv.log" 2>&1 &
    local srv_pid=$!
    pids+=($srv_pid)
    sleep 0.5
    echo "  server: 127.0.0.1:$ss_port (pid $srv_pid)"

    # Start SS local
    "$bin" -type local \
        -l "127.0.0.1:$local_port" \
        -s "127.0.0.1:$ss_port" \
        -m "$method" -p "$password" \
        -verbose \
        > "$WORKDIR/${label}_${method}_local.log" 2>&1 &
    local local_pid=$!
    pids+=($local_pid)
    sleep 0.5
    echo "  local: 127.0.0.1:$local_port (pid $local_pid)"

    # Smoke test
    local smoke_log="$WORKDIR/${label}_${method}_smoke.log"
    if "$PLOAD_BIN" -socks "127.0.0.1:$local_port" -target "127.0.0.1:$echo_port" \
        -c 2 -d 2s -size 64 > "$smoke_log" 2>&1; then
        echo "  smoke: OK"
    else
        echo "  smoke: FAILED — check $smoke_log"
        cat "$smoke_log"
        kill_pids "${pids[@]}"
        wait_pids "${pids[@]}"
        return 1
    fi

    # Launch load
    local load_log="$WORKDIR/${label}_${method}_load.log"
    "$PLOAD_BIN" -socks "127.0.0.1:$local_port" -target "127.0.0.1:$echo_port" \
        -c 100 -d 25s -size 512 > "$load_log" 2>&1 &
    local load_pid=$!
    pids+=($load_pid)
    echo "  load: pid $load_pid"

    # Warmup
    sleep 5

    # Collect pprof CPU profile
    local profile="$WORKDIR/${label}_${method}_cpu.pprof"
    local pp_url="http://127.0.0.1:$pp_port/debug/pprof/profile?seconds=10"
    echo "  pprof: collecting 10s profile ..."
    if curl -s -m 20 -o "$profile" "$pp_url"; then
        echo "  profile: $profile ($(ls -lh "$profile" | awk '{print $5}'))"
    else
        echo "  WARNING: pprof collection failed"
    fi

    # Wait for load to finish
    wait $load_pid 2>/dev/null || true
    echo "  load finished"

    # Results
    echo "  results:"
    grep -A6 "^Duration:" "$load_log" | sed 's/^/    /' || true

    # Cleanup this scenario's processes
    kill_pids "${pids[@]}"
    wait_pids "${pids[@]}"
    sleep 1
    echo ""
}

# ---- Step 4: Run ----

PASS_256="test-password-12345"
PASS_2022="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

run_scenario "old" "$OLD_BIN" "aes-256-gcm"                   "$PASS_256"
run_scenario "new" "$NEW_BIN" "aes-256-gcm"                   "$PASS_256"
run_scenario "old" "$OLD_BIN" "2022-blake3-aes-256-gcm"       "$PASS_2022"
run_scenario "new" "$NEW_BIN" "2022-blake3-aes-256-gcm"       "$PASS_2022"

# ---- Step 5: Compare ----

echo ""
echo "=========================================="
echo "  CPU Profile Diff: new vs old"
echo "  (negative delta = improvement)"
echo "=========================================="

for method in "aes-256-gcm" "2022-blake3-aes-256-gcm"; do
    old_p="$WORKDIR/old_${method}_cpu.pprof"
    new_p="$WORKDIR/new_${method}_cpu.pprof"
    if [ -f "$old_p" ] && [ -f "$new_p" ]; then
        echo ""
        echo "--- $method ---"
        go tool pprof -top -diff_base="$old_p" "$new_p" 2>&1 | head -40
    fi
done

echo ""
echo "=== Profiles: $WORKDIR ==="
ls -la "$WORKDIR"/*.pprof 2>/dev/null || echo "  (no profiles)"
echo ""
echo "=== Raw throughput ==="
for f in "$WORKDIR"/*_load.log; do
    echo "--- $(basename "$f") ---"
    grep -A6 "^Duration:" "$f" 2>/dev/null || echo "  (no data)"
done
