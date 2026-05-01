#!/bin/bash
# collect_profiles.sh — Collect pprof CPU profiles and generate flame graph SVGs
# for old and new shadowsocks-go binaries.

set -euo pipefail

BENCH_DIR=$(cd "$(dirname "$0")/.." && pwd)
OUTDIR="${1:-/tmp/perf_report}"
mkdir -p "$OUTDIR"

OLD_BIN="$OUTDIR/ss-old"
NEW_BIN="$OUTDIR/ss-new"
PLOAD_BIN="$OUTDIR/pload"

# ---- Build ----
echo "Building..."
cd "$BENCH_DIR"
go build -o "$NEW_BIN" ./cmd/shadowsocks/
go build -o "$PLOAD_BIN" ./cmd/pload/

OLD_TREE=$(mktemp -d /tmp/perf_old.XXXXXX)
git worktree add --detach "$OLD_TREE" 6e8c36c 2>&1
cd "$OLD_TREE"
go build -o "$OLD_BIN" ./cmd/shadowsocks/
cd "$BENCH_DIR"
trap "git worktree remove --force '$OLD_TREE' 2>/dev/null; rm -rf /tmp/perf_old.* 2>/dev/null" EXIT

echo "Binaries ready"
echo ""

free_port() { python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()"; }

# ---- Collect profile for one scenario ----
collect() {
    local label="$1" bin="$2" method="$3" password="$4"

    echo "=== $label $method ==="
    local -a pids=()

    # Echo server
    local ep=$(free_port)
    python3 -c "
import socket,threading,sys,signal
signal.signal(signal.SIGTERM,lambda*a:sys.exit(0))
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',$ep));s.listen(5)
def h(c):
    while True:
        d=c.recv(4096)
        if not d:break
        c.sendall(d)
    c.close()
while True:
    c,_=s.accept()
    threading.Thread(target=h,args=(c,),daemon=True).start()
" &
    pids+=($!)
    sleep 0.3

    local sp=$(free_port) lp=$(free_port) pp=$(free_port)

    # SS server
    "$bin" -type server -l "127.0.0.1:$sp" -m "$method" -p "$password" -pprof "127.0.0.1:$pp" > /dev/null 2>&1 &
    pids+=($!)
    sleep 0.5

    # SS local
    "$bin" -type local -l "127.0.0.1:$lp" -s "127.0.0.1:$sp" -m "$method" -p "$password" > /dev/null 2>&1 &
    pids+=($!)
    sleep 0.5

    # Smoke test
    "$PLOAD_BIN" -socks "127.0.0.1:$lp" -target "127.0.0.1:$ep" -c 1 -d 1s -size 64 > /dev/null 2>&1 || {
        echo "  smoke test FAILED"
        kill -9 "${pids[@]}" 2>/dev/null; wait "${pids[@]}" 2>/dev/null
        return 1
    }
    echo "  smoke OK pp=$pp"

    # Start load
    "$PLOAD_BIN" -socks "127.0.0.1:$lp" -target "127.0.0.1:$ep" -c 100 -d 25s -size 512 > "$OUTDIR/${label}_${method}_load.txt" 2>&1 &
    local load_pid=$!
    pids+=($load_pid)

    sleep 5

    # Collect CPU profile (15s for richer flame graph)
    local prof="$OUTDIR/${label}_${method}_cpu.pprof"
    echo "  collecting 15s CPU profile..."
    curl -s -m 25 -o "$prof" "http://127.0.0.1:$pp/debug/pprof/profile?seconds=15"
    echo "  profile: $(ls -lh "$prof" | awk '{print $5}')"

    # Collect heap profile too
    local heap="$OUTDIR/${label}_${method}_heap.pprof"
    curl -s -m 5 -o "$heap" "http://127.0.0.1:$pp/debug/pprof/heap"
    echo "  heap: $(ls -lh "$heap" | awk '{print $5}')"

    # Wait for load
    wait $load_pid 2>/dev/null || true
    echo "  load done"

    # Cleanup
    kill "${pids[@]}" 2>/dev/null || true
    wait "${pids[@]}" 2>/dev/null || true
    sleep 1

    # Generate flame graph SVG
    echo "  generating flame graph..."
    go tool pprof -svg -output="$OUTDIR/${label}_${method}_flame.svg" "$prof" 2>/dev/null
    echo "  flame: $(ls -lh "$OUTDIR/${label}_${method}_flame.svg" 2>/dev/null | awk '{print $5}')"

    # Generate diff flame graph (new vs old) if both exist
    local old_prof="$OUTDIR/old_${method}_cpu.pprof"
    local new_prof="$OUTDIR/new_${method}_cpu.pprof"
    if [ "$label" = "new" ] && [ -f "$old_prof" ] && [ -f "$new_prof" ]; then
        echo "  generating diff flame graph..."
        go tool pprof -svg -diff_base="$old_prof" -output="$OUTDIR/diff_${method}_flame.svg" "$new_prof" 2>/dev/null
        echo "  diff: $(ls -lh "$OUTDIR/diff_${method}_flame.svg" 2>/dev/null | awk '{print $5}')"
    fi

    echo ""
}

PASS_256="test-password-12345"
PASS_2022="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

collect "old" "$OLD_BIN" "aes-256-gcm"             "$PASS_256"
collect "new" "$NEW_BIN" "aes-256-gcm"             "$PASS_256"
collect "old" "$OLD_BIN" "2022-blake3-aes-256-gcm" "$PASS_2022"
collect "new" "$NEW_BIN" "2022-blake3-aes-256-gcm" "$PASS_2022"

echo "=== Profiles in $OUTDIR ==="
ls -la "$OUTDIR"/
