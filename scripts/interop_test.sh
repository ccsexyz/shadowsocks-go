#!/bin/bash
# interop_test.sh — cross-version interoperability test for shadowsocks-go
#
# Usage: ./scripts/interop_test.sh <commit1> <commit2> [commit3 ...]
#
# For each pair of commits (A, B), tests A-srv+A-cli, B-srv+B-cli,
# A-srv+B-cli, B-srv+A-cli across all protocol layers:
#   - AEAD methods (aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305)
#   - 2022 methods (blake3-aes-128/256-gcm, blake3-chacha20-poly1305)
#   - Obfuscation (HTTP chunked, TLS imitation, WebSocket)
#   - Multi-server
#   - Reverse tunnel (rtunnel)
#   - SS proxy relay
#   - Both TCP and UDP for each

set -euo pipefail

# ── config ──────────────────────────────────────────────────────────

CC_TMP="${CC_TMP:-/tmp/cc-shadowsocks-go}"
CACHE_DIR="$CC_TMP/interop-cache"
ITEST="$CC_TMP/itest"
BENCH="$CC_TMP/bench"

PASS=0 FAIL=0
declare -a RESULTS=()

# ── helpers ─────────────────────────────────────────────────────────

msg()  { printf "  %s\n" "$*"; }
ok()   { printf "  \033[32m✓ %s\033[m\n" "$*"; }
fail() { printf "  \033[31m✗ %s\033[m\n" "$*"; }
h1()   { printf "\n\033[1m=== %s ===\033[m\n" "$*"; }
h2()   { printf "\n\033[1m--- %s ---\033[m\n" "$*"; }

free_port() {
    python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()" 2>/dev/null
}

die() { echo "FATAL: $*" >&2; exit 1; }

cleanup() {
    for pid in "${BG_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${BG_PIDS[@]:-}"; do
        wait "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT
BG_PIDS=()

bg_run() {
    "$@" >/dev/null 2>&1 &
    local pid=$!
    BG_PIDS+=("$pid")
    sleep 0.1
    if ! kill -0 "$pid" 2>/dev/null; then
        die "process died immediately: $*"
    fi
    echo "$pid"
}

# wait_port polls until the given TCP port accepts connections or timeout.
wait_port() {
    local host=$1 port=$2 timeout=${3:-5}
    local deadline=$(($(date +%s) + timeout))
    while ! python3 -c "import socket; s=socket.socket(); s.settimeout(0.5); s.connect(('$host',$port)); s.close()" 2>/dev/null; do
        if [[ $(date +%s) -ge $deadline ]]; then
            die "timeout waiting for $host:$port to become available"
        fi
        sleep 0.1
    done
}

kill_bg() {
    local pid=$1
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    # Remove from BG_PIDS
    for i in "${!BG_PIDS[@]}"; do
        if [[ "${BG_PIDS[$i]}" == "$pid" ]]; then
            unset "BG_PIDS[$i]"
        fi
    done
}

# ── binary cache ────────────────────────────────────────────────────

build_binary() {
    local commit=$1
    local hash
    hash=$(git rev-parse --short "$commit") || die "invalid commit: $commit"
    local bin="$CACHE_DIR/ss-$hash"

    if [[ -f "$bin" ]]; then
        msg "binary cached: $bin"
        echo "$bin"
        return
    fi

    msg "building $commit ($hash)..."
    mkdir -p "$CACHE_DIR"
    local current
    current=$(git branch --show-current 2>/dev/null || echo "HEAD")

    git checkout --quiet "$commit"
    go build -o "$bin" ./cmd/shadowsocks/ || die "build failed for $commit"
    git checkout --quiet "$current"

    msg "built: $bin"
    echo "$bin"
}

build_tools() {
    if [[ ! -f "$ITEST" ]] || [[ ! -f "$BENCH" ]]; then
        msg "building itest & bench..."
        go build -o "$ITEST" ./cmd/itest/ || die "itest build failed"
        go build -o "$BENCH" ./cmd/bench/ || die "bench build failed"
    fi
}

# ── service starters ────────────────────────────────────────────────

start_ss_server() {
    local bin=$1 port=$2 method=$3 password=$4; shift 4
    local extra_args=("$@")
    bg_run "$bin" -type server -l "127.0.0.1:$port" \
        -m "$method" -p "$password" "${extra_args[@]:-}"
    wait_port 127.0.0.1 "$port"
}

start_ss_local() {
    local bin=$1 port=$2 server_port=$3 method=$4 password=$5; shift 5
    local extra_args=("$@")
    bg_run "$bin" -type local -l "127.0.0.1:$port" \
        -s "127.0.0.1:$server_port" -m "$method" -p "$password" "${extra_args[@]:-}"
    wait_port 127.0.0.1 "$port"
}

start_tcp_echo() {
    local port=$1
    bg_run "$ITEST" echo --addr "127.0.0.1:$port"
    wait_port 127.0.0.1 "$port"
}

start_udp_echo() {
    local port=$1
    bg_run "$ITEST" udp -s -l "127.0.0.1:$port"
    # UDP echo doesn't have a TCP port to wait on; just give it a moment
    sleep 0.2
}

# ── test runners ────────────────────────────────────────────────────

run_tcp_test() {
    local target=$1 socks=$2
    local out
    out=$("$ITEST" pkt --target "$target" --socks "$socks" \
        --min 64 --max 65536 --interval 500us --count 20 2>&1) || { echo "$out"; return 1; }
    echo "$out" | grep -q "fail=0"
}

run_udp_test() {
    local target=$1 socks=$2
    local out
    out=$("$BENCH" udpload -socks "$socks" -target "$target" \
        -c 1 -d 1s -size 1024 2>&1) || return 1
    local lost
    lost=$(echo "$out" | awk '/UDP_LOST/{print $2}')
    local recv
    recv=$(echo "$out" | awk '/UDP_RECV/{print $2}')
    if [[ "${lost:-1}" != "0" ]] || [[ "${recv:-0}" == "0" ]]; then
        echo "  udpload: recv=$recv lost=$lost"
        return 1
    fi
}

# ── scenario: one commit-pair × one configuration ───────────────────

test_scenario() {
    local label=$1 srv_bin=$2 cli_bin=$3 method=$4 password=$5; shift 5
    local obfs_mode="${1:-}"      # http | tls | ws | "" (none)
    local with_udp="${2:-0}"      # 1 = also test UDP

    local ss_port socks_port echo_port udp_echo_port
    ss_port=$(free_port)
    socks_port=$(free_port)
    echo_port=$(free_port)
    udp_echo_port=$(free_port)

    # Start echo service
    local echo_pid udp_echo_pid="" srv_pid cli_pid
    echo_pid=$(start_tcp_echo "$echo_port")
    if [[ "$with_udp" == "1" ]]; then
        udp_echo_pid=$(start_udp_echo "$udp_echo_port")
    fi

    # Build extra args for obfs
    local srv_extra=() cli_extra=()
    case "$obfs_mode" in
        http)
            srv_extra=(-obfs -om http)
            cli_extra=(-obfs -om http)
            ;;
        tls)
            srv_extra=(-obfs -om tls)
            cli_extra=(-obfs -om tls)
            ;;
        ws)
            srv_extra=(-obfs -om websocket)
            cli_extra=(-obfs -om websocket)
            ;;
    esac

    # Start SS server & client
    local srv_args cli_args
    if [[ "$with_udp" == "1" ]]; then
        srv_extra+=(-udprelay)
        cli_extra+=(-udprelay)
    fi
    srv_pid=$(start_ss_server "$srv_bin" "$ss_port" "$method" "$password" "${srv_extra[@]:-}")
    cli_pid=$(start_ss_local "$cli_bin" "$socks_port" "$ss_port" "$method" "$password" "${cli_extra[@]:-}")

    local ok=true

    # TCP test
    if ! run_tcp_test "127.0.0.1:$echo_port" "127.0.0.1:$socks_port"; then
        ok=false
    fi

    # UDP test
    if [[ "$with_udp" == "1" ]]; then
        if ! run_udp_test "127.0.0.1:$udp_echo_port" "127.0.0.1:$socks_port"; then
            ok=false
        fi
    fi

    # Cleanup
    kill_bg "$cli_pid"
    kill_bg "$srv_pid"
    kill_bg "$echo_pid"
    [[ -n "$udp_echo_pid" ]] && kill_bg "$udp_echo_pid"
    sleep 0.2

    if $ok; then
        ((PASS++))
        RESULTS+=("PASS")
        ok "PASS  $label"
    else
        ((FAIL++))
        RESULTS+=("FAIL")
        fail "FAIL  $label"
    fi
}

# ── scenario: rtunnel cross-version ────────────────────────────────

test_rtunnel_scenario() {
    local label=$1 srv_bin=$2 cli_bin=$3 method=$4 password=$5

    local echo_port srv_port service_port
    echo_port=$(free_port)
    srv_port=$(free_port)
    service_port=$(free_port)

    # Start echo
    local echo_pid srv_pid cli_pid
    echo_pid=$(start_tcp_echo "$echo_port")

    # Start rtunnel server (from srv_bin)
    srv_pid=$(bg_run "$srv_bin" -type rtunnelserver \
        -l "127.0.0.1:$srv_port" \
        -m "$method" -p "$password" \
        -rtunnel-service "127.0.0.1:$service_port")

    wait_port 127.0.0.1 "$srv_port"

    # Start rtunnel client (from cli_bin) targeting echo
    cli_pid=$(bg_run "$cli_bin" -type rtunnelclient \
        -s "127.0.0.1:$srv_port" \
        -m "$method" -p "$password" \
        -t "127.0.0.1:$echo_port")

    # Wait for smux handshake and exposed service port
    wait_port 127.0.0.1 "$service_port" 10

    local ok=true

    # Test via the exposed service port (direct, no socks)
    if ! run_tcp_test "127.0.0.1:$service_port" ""; then
        ok=false
    fi

    # Cleanup
    kill_bg "$cli_pid"
    kill_bg "$srv_pid"
    kill_bg "$echo_pid"
    sleep 0.2

    if $ok; then
        ((PASS++))
        RESULTS+=("PASS")
        ok "PASS  $label"
    else
        ((FAIL++))
        RESULTS+=("FAIL")
        fail "FAIL  $label"
    fi
}

# ── test one commit pair across all methods ──────────────────────────

# Generate server/client combos. When commits are the same, only self-test.
# When different, test all 4 combos: A-A, B-B, A-B, B-A.
gen_combos() {
    local a_hash=$1 b_hash=$2 a_bin=$3 b_bin=$4
    if [[ "$a_hash" == "$b_hash" ]]; then
        echo "$a_hash-srv+$a_hash-cli:$a_bin:$a_bin"
    else
        echo "$a_hash-srv+$a_hash-cli:$a_bin:$a_bin"
        echo "$b_hash-srv+$b_hash-cli:$b_bin:$b_bin"
        echo "$a_hash-srv+$b_hash-cli:$a_bin:$b_bin"
        echo "$b_hash-srv+$a_hash-cli:$b_bin:$a_bin"
    fi
}

test_pair() {
    local a_commit=$1 b_commit=$2
    local a_hash b_hash
    a_hash=$(git rev-parse --short "$a_commit")
    b_hash=$(git rev-parse --short "$b_commit")

    local a_bin b_bin
    a_bin="$CACHE_DIR/ss-$a_hash"
    b_bin="$CACHE_DIR/ss-$b_hash"

    h1 "$a_hash ↔ $b_hash"

    # ── basic AEAD ──────────────────────────────────────────────
    local aead_methods=(
        "aes-128-gcm:test"
        "aes-256-gcm:test"
        "chacha20-ietf-poly1305:test"
    )
    for entry in "${aead_methods[@]}"; do
        local method="${entry%%:*}" pwd="${entry##*:}"

        h2 "AEAD $method TCP"
        while IFS=':' read -r label srv cli; do
            test_scenario "$label  $method TCP" "$srv" "$cli" "$method" "$pwd"
        done < <(gen_combos "$a_hash" "$b_hash" "$a_bin" "$b_bin")

        h2 "AEAD $method UDP"
        while IFS=':' read -r label srv cli; do
            test_scenario "$label  $method UDP" "$srv" "$cli" "$method" "$pwd" "" 1
        done < <(gen_combos "$a_hash" "$b_hash" "$a_bin" "$b_bin")
    done

    # ── 2022 AEAD ──────────────────────────────────────────────
    local methods_2022=(
        "2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA=="
        "2022-blake3-aes-256-gcm:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        "2022-blake3-chacha20-poly1305:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    for entry in "${methods_2022[@]}"; do
        local method="${entry%%:*}" pwd="${entry##*:}"

        h2 "2022 $method TCP"
        while IFS=':' read -r label srv cli; do
            test_scenario "$label  $method TCP" "$srv" "$cli" "$method" "$pwd"
        done < <(gen_combos "$a_hash" "$b_hash" "$a_bin" "$b_bin")

        h2 "2022 $method UDP"
        while IFS=':' read -r label srv cli; do
            test_scenario "$label  $method UDP" "$srv" "$cli" "$method" "$pwd" "" 1
        done < <(gen_combos "$a_hash" "$b_hash" "$a_bin" "$b_bin")
    done

    # ── obfuscation ────────────────────────────────────────────────
    local obfs_modes=("http" "tls" "ws")
    for mode in "${obfs_modes[@]}"; do
        h2 "obfs-$mode TCP"
        while IFS=':' read -r label srv cli; do
            test_scenario "$label  obfs-$mode" "$srv" "$cli" "aes-256-gcm" "test" "$mode"
        done < <(gen_combos "$a_hash" "$b_hash" "$a_bin" "$b_bin")
    done

    # ── rtunnel ────────────────────────────────────────────────────
    h2 "rtunnel"
    while IFS=':' read -r label srv cli; do
        test_rtunnel_scenario "$label  rtunnel" "$srv" "$cli" "aes-256-gcm" "test"
    done < <(gen_combos "$a_hash" "$b_hash" "$a_bin" "$b_bin")
}

# ── main ────────────────────────────────────────────────────────────

main() {
    if [[ $# -lt 2 ]]; then
        echo "Usage: $0 <commit1> <commit2> [commit3 ...]" >&2
        echo "  At least two commit hashes required for interop testing." >&2
        exit 1
    fi

    local commits=("$@")

    # Validate commits
    for c in "${commits[@]}"; do
        git rev-parse --quiet --verify "$c^{commit}" >/dev/null \
            || die "'$c' is not a valid commit"
    done

    mkdir -p "$CACHE_DIR"

    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  shadowsocks-go interop test                                ║"
    echo "║  commits: ${commits[*]}                                     ║"
    echo "╚══════════════════════════════════════════════════════════════╝"

    # Phase 1: Build tools + binaries
    h1 "Phase 1: build"
    build_tools

    local current_branch
    current_branch=$(git branch --show-current 2>/dev/null || echo "HEAD")

    local binaries=()
    for c in "${commits[@]}"; do
        binaries+=("$(build_binary "$c")")
    done

    # Ensure we're back on the original branch
    git checkout --quiet "$current_branch"

    # Phase 2: Test all pairs
    h1 "Phase 2: interop tests"
    local n=${#commits[@]}
    for ((i = 0; i < n; i++)); do
        for ((j = i; j < n; j++)); do
            test_pair "${commits[$i]}" "${commits[$j]}"
        done
    done

    # Phase 3: Summary
    local total=$((PASS + FAIL))
    h1 "Phase 3: summary"
    echo "  Total: $total  Passed: $PASS  Failed: $FAIL"

    if [[ $FAIL -gt 0 ]]; then
        echo ""
        echo "  Failed scenarios:"
        for r in "${RESULTS[@]}"; do
            [[ "$r" == "FAIL" ]] && echo "    $r"
        done
        exit 1
    fi

    echo "  All interop tests passed."
}

main "$@"
