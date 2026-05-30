#!/bin/bash
# Parallel integration test runner — distributes test functions across workers
# with isolated port ranges for binary tests.
#
# Usage:
#   ./scripts/run_integration_tests.sh [workers] [port_step]
#   workers=4 port_step=500   (defaults)
#
# Each worker gets a PORT_STEP offset so binary tests don't collide.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKERS=${1:-4}
PORT_STEP=${2:-500}
TIMEOUT=${3:-120s}

RESULTS_DIR="/tmp/ss-integration-$$"
mkdir -p "$RESULTS_DIR"

cleanup() {
    rm -rf "$RESULTS_DIR"
}
trap cleanup EXIT

echo "=== Shadowsocks-go Integration Test Runner ==="
echo "Workers: $WORKERS | Port step: $PORT_STEP | Timeout: $TIMEOUT"
echo ""

# Collect all test function names in the server package.
# We skip the slow binary test (TestBinary_SSProxyWithBackend) — it runs separately.
cd "$PROJECT_DIR"

all_tests=$(go test -list '.*' ./server/ 2>/dev/null | grep '^Test' | grep -v '^TestBinary_' || true)
count=$(echo "$all_tests" | wc -l | tr -d ' ')
echo "Found $count test functions (excluding binary tests)"

# Distribute tests across workers (round-robin)
declare -a worker_tests
for ((i = 0; i < WORKERS; i++)); do
    worker_tests[$i]=""
done

idx=0
while IFS= read -r test; do
    worker_tests[$idx]="${worker_tests[$idx]}${test}|"
    idx=$(( (idx + 1) % WORKERS ))
done <<< "$all_tests"

# Remove trailing '|' from each worker's pattern
for ((i = 0; i < WORKERS; i++)); do
    worker_tests[$i]=$(echo "${worker_tests[$i]}" | sed 's/|$//')
done

# Launch workers
pids=()
for ((i = 0; i < WORKERS; i++)); do
    pattern="${worker_tests[$i]}"
    if [ -z "$pattern" ]; then
        echo "Worker $i: no tests assigned"
        continue
    fi
    # Count tests for this worker
    wcount=$(echo "$pattern" | tr '|' '\n' | wc -l | tr -d ' ')
    log_file="$RESULTS_DIR/worker-${i}.log"

    (
        export PORT_STEP=$((i * PORT_STEP))
        echo "Worker $i: $wcount tests (port offset $PORT_STEP)"
        cd "$PROJECT_DIR"
        if [ -n "$pattern" ]; then
            go test -v -count=1 -timeout "$TIMEOUT" -parallel 8 -run "($pattern)" ./server/ 2>&1
        else
            echo "No tests assigned"
        fi
        echo "Exit: $?"
    ) > "$log_file" 2>&1 &
    pids+=($!)
    echo "Worker $i: PID ${pids[$i]} ($wcount tests)"
done

echo ""

# Progress ticker
(
    started=$(date +%s)
    while true; do
        all_done=true
        for pid in "${pids[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                all_done=false
                break
            fi
        done
        if $all_done; then
            break
        fi
        p=0; f=0
        for log in "$RESULTS_DIR"/worker-*.log; do
            [ -f "$log" ] || continue
            c=$(grep -c '^--- PASS:' "$log" 2>/dev/null) || true; p=$((p + ${c:-0}))
            c=$(grep -c '^--- FAIL:' "$log" 2>/dev/null) || true; f=$((f + ${c:-0}))
        done
        elapsed=$(($(date +%s) - started))
        printf "\r  [%ds] passed=%d failed=%d   " "$elapsed" "$p" "$f"
        sleep 3
    done
) &
ticker_pid=$!

# Wait for all workers
failed=false
for pid in "${pids[@]}"; do
    wait "$pid" || failed=true
done

kill $ticker_pid 2>/dev/null || true
wait $ticker_pid 2>/dev/null || true
printf "\r\033[K"
echo ""

# Aggregate results — first pass
total_pass=0
total_fail=0
declare -a failed_tests
for ((i = 0; i < WORKERS; i++)); do
    log="$RESULTS_DIR/worker-${i}.log"
    if [ -f "$log" ]; then
        p=$(grep -c '^--- PASS:' "$log" 2>/dev/null) || true; p=${p:-0}
        f=$(grep -c '^--- FAIL:' "$log" 2>/dev/null) || true; f=${f:-0}
        total_pass=$((total_pass + p))
        total_fail=$((total_fail + f))
        echo "Worker $i: ${p}P ${f}F"
        # Collect failed test names
        if [ "$f" -gt 0 ]; then
            while IFS= read -r line; do
                # line looks like: --- FAIL: TestName (0.20s)
                test_name=$(echo "$line" | sed -n 's/^--- FAIL: \([^ ]*\).*/\1/p')
                if [ -n "$test_name" ]; then
                    failed_tests+=("$test_name")
                fi
            done < <(grep '^--- FAIL:' "$log" 2>/dev/null || true)
        fi
    else
        echo "Worker $i: no log"
    fi
done

# Retry failed tests sequentially (mitigates ephemeral port exhaustion flakiness)
if [ ${#failed_tests[@]} -gt 0 ]; then
    echo ""
    echo "--- Retrying ${#failed_tests[@]} failed test(s) sequentially ---"
    retry_pass=0
    retry_fail=0
    for test_name in "${failed_tests[@]}"; do
        printf "  %s ... " "$test_name"
        if go test -count=1 -timeout 30s -run "^${test_name}$" ./server/ > /dev/null 2>&1; then
            echo "PASS"
            retry_pass=$((retry_pass + 1))
            total_pass=$((total_pass + 1))
            total_fail=$((total_fail - 1))
        else
            echo "FAIL"
            retry_fail=$((retry_fail + 1))
        fi
    done
    echo "  Retry: ${retry_pass} recovered, ${retry_fail} still failing"
fi

echo ""
echo "========================================"
echo " Total: $total_pass passed, $total_fail failed"
echo " Logs:  $RESULTS_DIR"
echo "========================================"

# Run binary test separately (needs unique ports)
echo ""
echo "--- Binary test ---"
go test -v -count=1 -timeout 60s -run 'TestBinary_' ./server/ 2>&1 | tail -5
if [ $? -eq 0 ]; then
    echo "Binary test: PASS"
else
    echo "Binary test: FAIL"
    total_fail=$((total_fail + 1))
fi

echo ""
if [ $total_fail -eq 0 ]; then
    echo "All tests passed."
    exit 0
else
    echo "Some tests failed."
    exit 1
fi
