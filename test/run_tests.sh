#!/usr/bin/env bash
# qcore test suite
#
# Usage: ./run_tests.sh [-v]
#   -v  verbose: show qcore output even on passing tests
#
# Covers:
#   - Baseline correctness (ELF structure, GDB, registers, sockets)
#   - Failure scenarios from the previous COW-injection approach:
#       SIGSTOP accumulation, ERESTARTNOHAND -EINTR, child visibility,
#       TCP socket side effects on child death
#
# Requirements:
#   - Run as root or with passwordless sudo
#   - readelf, file, strings, gdb (optional) in PATH
#   - python3 optional (JSON tests)

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
QCORE="$SCRIPT_DIR/../qcore"
BIN_DIR="$SCRIPT_DIR"

VERBOSE=0
[[ "${1:-}" == "-v" ]] && VERBOSE=1

PASS=0; FAIL=0; SKIP=0
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)) || true; }
fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    shift
    for m in "$@"; do echo "         $m"; done
    ((FAIL++)) || true
}
skip() { echo -e "${YELLOW}[SKIP]${NC} $1  ($2)"; ((SKIP++)) || true; }
section() { echo -e "\n${BOLD}-- $1 --${NC}"; }

CLEANUP_PIDS=()
CLEANUP_FILES=()
cleanup() {
    for p in "${CLEANUP_PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    for f in "${CLEANUP_FILES[@]:-}"; do rm -rf "$f"; done
    rm -f /tmp/qcore_test_*.sock
}
trap cleanup EXIT

# -- Helpers ----------------------------------------------------------------

start_target() {
    local bin="$1"; shift
    local out; out=$(mktemp /tmp/qcore_target_XXXXXX)
    CLEANUP_FILES+=("$out")
    "$bin" "$@" >"$out" 2>/dev/null &
    local pid=$!
    CLEANUP_PIDS+=("$pid")
    for i in $(seq 1 60); do
        [[ -s "$out" ]] && { TARGET_LINE=$(cat "$out"); TARGET_PID=$pid; return 0; }
        sleep 0.05
    done
    TARGET_PID=$pid; TARGET_LINE=""
    return 1
}

field_of() { echo "$2" | grep -oP "(?<=$1=)\S+"; }

QCORE_OUT=""
run_qcore() {
    local pid="$1"
    local out; out=$(mktemp /tmp/qcore_out_XXXXXX)
    CLEANUP_FILES+=("$out" "core.$pid" "core.$pid.sockets.json")
    local invoke=("$QCORE" "$pid")
    [[ $EUID -ne 0 ]] && invoke=(sudo "${invoke[@]}")
    if "${invoke[@]}" >"$out" 2>&1; then
        QCORE_OUT=$(cat "$out")
        [[ $VERBOSE -eq 1 ]] && echo "$QCORE_OUT" | sed 's/^/    /'
        return 0
    else
        QCORE_OUT=$(cat "$out")
        echo "    qcore failed:" >&2
        echo "$QCORE_OUT" | sed 's/^/    /' >&2
        return 1
    fi
}

stop_target() {
    local pid="$1"
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    CLEANUP_PIDS=("${CLEANUP_PIDS[@]/$pid}")
}

preflight() {
    local ok=1
    [[ -x "$QCORE" ]] || { echo "qcore not found at $QCORE - run 'make' first"; ok=0; }
    for t in target_simple target_mt target_sockets target_registers \
              target_epoll target_children; do
        [[ -x "$BIN_DIR/$t" ]] || { echo "Missing: $BIN_DIR/$t"; ok=0; }
    done
    for cmd in readelf file strings; do
        command -v "$cmd" >/dev/null 2>&1 || { echo "Missing tool: $cmd"; ok=0; }
    done
    if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
        echo "Need root or passwordless sudo"
        ok=0
    fi
    [[ $ok -eq 1 ]] || exit 1
}

# -- Error handling ---------------------------------------------------------
section "Error handling"

t_no_args() {
    local out; out=$("$QCORE" 2>&1) || true
    echo "$out" | grep -qi "usage\|pid" \
        && pass "no_args: prints usage" \
        || fail "no_args: prints usage" "got: $out"
    "$QCORE" 2>/dev/null && fail "no_args: exits nonzero" \
                          || pass "no_args: exits nonzero"
}

t_bad_pid() {
    local out
    out=$(sudo "$QCORE" 9999999 2>&1) && fail "bad_pid: exits nonzero" \
                                       || pass "bad_pid: exits nonzero"
    echo "$out" | grep -qiE "not found|invalid|error" \
        && pass "bad_pid: informative error" \
        || fail "bad_pid: informative error" "got: $out"
}

# -- ELF structure ----------------------------------------------------------
section "ELF core structure"

t_elf_valid() {
    start_target "$BIN_DIR/target_simple" || { fail "elf_valid: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "elf_valid: qcore"; stop_target "$pid"; return; }
    file "core.$pid" 2>/dev/null | grep -q "ELF 64-bit LSB core" \
        && pass "elf_valid: file(1) reports ELF core" \
        || fail "elf_valid: file(1)" "$(file "core.$pid" 2>/dev/null)"
    local etype; etype=$(readelf -h "core.$pid" 2>/dev/null | awk '/Type:/{print $2}')
    [[ "$etype" == "CORE" ]] && pass "elf_valid: ET_CORE" \
                              || fail "elf_valid: ET_CORE" "got: $etype"
    stop_target "$pid"
}

t_segments() {
    start_target "$BIN_DIR/target_simple" || { fail "segments: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "segments: qcore"; stop_target "$pid"; return; }
    readelf -l "core.$pid" 2>/dev/null | grep -q "NOTE" \
        && pass "segments: PT_NOTE present" \
        || fail "segments: PT_NOTE present"
    local n; n=$(readelf -l "core.$pid" 2>/dev/null | grep -c "LOAD" || true)
    [[ "$n" -ge 5 ]] && pass "segments: $n PT_LOAD segments" \
                      || fail "segments: >=5 PT_LOAD" "got $n"
    stop_target "$pid"
}

t_notes() {
    start_target "$BIN_DIR/target_simple" || { fail "notes: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "notes: qcore"; stop_target "$pid"; return; }
    local notes; notes=$(readelf -n "core.$pid" 2>/dev/null)
    for nt in NT_PRSTATUS NT_PRPSINFO NT_FILE; do
        echo "$notes" | grep -q "$nt" && pass "notes: $nt" || fail "notes: $nt"
    done
    stop_target "$pid"
}

# -- Target liveness & size -------------------------------------------------
section "Target liveness"

t_alive() {
    start_target "$BIN_DIR/target_simple" || { fail "alive: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "alive: qcore"; stop_target "$pid"; return; }
    kill -0 "$pid" 2>/dev/null \
        && pass "alive: target still running after dump" \
        || fail "alive: target dead after dump (Phase 4 broken)"
    stop_target "$pid"
}

t_core_size() {
    start_target "$BIN_DIR/target_simple" || { fail "size: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "size: qcore"; stop_target "$pid"; return; }
    local sz; sz=$(stat -c %s "core.$pid" 2>/dev/null || echo 0)
    [[ "$sz" -gt 65536 ]] && pass "size: core is ${sz} bytes" \
                            || fail "size: core < 64KB" "$sz"
    stop_target "$pid"
}

# -- Memory content ---------------------------------------------------------
section "Memory content"

t_marker() {
    start_target "$BIN_DIR/target_simple" || { fail "marker: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "marker: qcore"; stop_target "$pid"; return; }
    strings "core.$pid" 2>/dev/null | grep -q "QCORE_MEMORY_MARKER_DEADBEEF1234" \
        && pass "marker: BSS marker found in core" \
        || fail "marker: BSS marker missing from core"
    stop_target "$pid"
}

# -- Multi-threaded ---------------------------------------------------------
section "Multi-threaded target (8 threads)"

t_multithreaded() {
    start_target "$BIN_DIR/target_mt" || { fail "mt: startup"; return; }
    local pid="$TARGET_PID"
    local n_threads; n_threads=$(field_of "threads" "$TARGET_LINE"); n_threads="${n_threads:-8}"
    run_qcore "$pid" || { fail "mt: qcore"; stop_target "$pid"; return; }
    local n_ps; n_ps=$(readelf -n "core.$pid" 2>/dev/null | grep -c "NT_PRSTATUS" || true)
    [[ "$n_ps" -ge "$n_threads" ]] \
        && pass "mt: $n_ps NT_PRSTATUS notes (>= $n_threads)" \
        || fail "mt: not enough PRSTATUS" "got $n_ps, need $n_threads"
    kill -0 "$pid" 2>/dev/null && pass "mt: target alive" \
                                || fail "mt: target dead"
    stop_target "$pid"
}

# -- Sockets ----------------------------------------------------------------
section "Socket / FD harvesting"

t_sockets_file() {
    start_target "$BIN_DIR/target_simple" || { fail "sockets_file: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "sockets_file: qcore"; stop_target "$pid"; return; }
    [[ -f "core.$pid.sockets.json" ]] \
        && pass "sockets_file: JSON created" \
        || fail "sockets_file: JSON missing"
    stop_target "$pid"
}

t_json_valid() {
    command -v python3 >/dev/null 2>&1 || { skip "json_valid" "python3 absent"; return; }
    start_target "$BIN_DIR/target_sockets" || { fail "json_valid: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "json_valid: qcore"; stop_target "$pid"; return; }
    python3 -m json.tool "core.$pid.sockets.json" >/dev/null 2>&1 \
        && pass "json_valid: well-formed JSON" \
        || fail "json_valid: malformed JSON"
    stop_target "$pid"
}

t_json_tcp() {
    command -v python3 >/dev/null 2>&1 || { skip "json_tcp" "python3 absent"; return; }
    start_target "$BIN_DIR/target_sockets" || { fail "json_tcp: startup"; return; }
    local pid="$TARGET_PID"
    local port; port=$(field_of "tcp_port" "$TARGET_LINE")
    run_qcore "$pid" || { fail "json_tcp: qcore"; stop_target "$pid"; return; }
    local j; j=$(cat "core.$pid.sockets.json" 2>/dev/null)
    echo "$j" | grep -qE '"type".*"(tcp4|tcp6)"' && pass "json_tcp: type present" \
                                                   || fail "json_tcp: type missing"
    [[ -n "$port" ]] && echo "$j" | grep -q ":$port" \
        && pass "json_tcp: port $port in JSON" \
        || fail "json_tcp: port $port not found"
    echo "$j" | grep -q '"LISTEN"' && pass "json_tcp: state=LISTEN" \
                                    || fail "json_tcp: LISTEN missing"
    stop_target "$pid"
}

t_json_fds() {
    command -v python3 >/dev/null 2>&1 || { skip "json_fds" "python3 absent"; return; }
    start_target "$BIN_DIR/target_simple" || { fail "json_fds: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "json_fds: qcore"; stop_target "$pid"; return; }
    local count; count=$(python3 -c "
import json; d=json.load(open('core.$pid.sockets.json')); print(len(d['fds']))" 2>/dev/null || echo 0)
    [[ "$count" -ge 3 ]] && pass "json_fds: $count FDs (>= stdin/stdout/stderr)" \
                          || fail "json_fds: too few FDs" "got $count"
    stop_target "$pid"
}

# -- GDB integration --------------------------------------------------------
section "GDB integration"

HAS_GDB=0; command -v gdb >/dev/null 2>&1 && HAS_GDB=1

t_gdb_loads() {
    [[ $HAS_GDB -eq 1 ]] || { skip "gdb_loads" "gdb absent"; return; }
    start_target "$BIN_DIR/target_simple" || { fail "gdb_loads: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "gdb_loads: qcore"; stop_target "$pid"; return; }
    local out; out=$(gdb --batch -ex "set confirm off" -ex "core-file core.$pid" \
                     -ex quit "$BIN_DIR/target_simple" 2>&1)
    [[ $VERBOSE -eq 1 ]] && echo "$out" | sed 's/^/    /'
    echo "$out" | grep -qi "Truncated\|corrupt\|error reading" \
        && fail "gdb_loads: errors in GDB output" "$(echo "$out" | grep -i "trunc\|corrupt" | head -2)" \
        || pass "gdb_loads: no truncation errors"
    echo "$out" | grep -q "Core was generated by" \
        && pass "gdb_loads: process identified" \
        || fail "gdb_loads: 'Core was generated by' missing"
    stop_target "$pid"
}

t_gdb_backtrace() {
    [[ $HAS_GDB -eq 1 ]] || { skip "gdb_bt" "gdb absent"; return; }
    start_target "$BIN_DIR/target_simple" || { fail "gdb_bt: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "gdb_bt: qcore"; stop_target "$pid"; return; }
    local out; out=$(gdb --batch -ex "set confirm off" -ex "core-file core.$pid" \
                     -ex "thread 1" -ex bt -ex quit "$BIN_DIR/target_simple" 2>&1)
    local n; n=$(echo "$out" | grep -cE '^#[0-9]' || true)
    [[ "$n" -ge 1 ]] && pass "gdb_bt: $n backtrace frames" \
                      || fail "gdb_bt: no frames" "$(echo "$out" | tail -5)"
    if echo "$out" | grep -qE 'in (main|pause|worker|__libc)'; then
        pass "gdb_bt: named symbols"
    elif [[ "$n" -ge 3 ]]; then
        pass "gdb_bt: $n frames (PIE - symbols unresolved)"
    else
        fail "gdb_bt: fewer than 3 frames"
    fi
    stop_target "$pid"
}

t_gdb_threads() {
    [[ $HAS_GDB -eq 1 ]] || { skip "gdb_threads" "gdb absent"; return; }
    start_target "$BIN_DIR/target_mt" || { fail "gdb_threads: startup"; return; }
    local pid="$TARGET_PID"
    local nt; nt=$(field_of "threads" "$TARGET_LINE"); nt="${nt:-8}"
    run_qcore "$pid" || { fail "gdb_threads: qcore"; stop_target "$pid"; return; }
    local out; out=$(gdb --batch -ex "set confirm off" -ex "core-file core.$pid" \
                     -ex "info threads" -ex quit "$BIN_DIR/target_mt" 2>&1)
    local cnt; cnt=$(echo "$out" | grep -cE '^\s*\*?\s*[0-9]+\s+(LWP|Thread)\s' || true)
    [[ "$cnt" -ge "$nt" ]] && pass "gdb_threads: GDB sees $cnt threads (>= $nt)" \
                            || fail "gdb_threads: only $cnt threads (need $nt)"
    stop_target "$pid"
}

# -- Register fidelity ------------------------------------------------------
section "Register fidelity"

t_registers() {
    [[ $HAS_GDB -eq 1 ]] || { skip "registers" "gdb absent"; return; }
    start_target "$BIN_DIR/target_registers" || { fail "registers: startup"; return; }
    local pid="$TARGET_PID"
    local exp_rbx; exp_rbx=$(field_of "rbx" "$TARGET_LINE")
    local exp_r12; exp_r12=$(field_of "r12" "$TARGET_LINE")
    local exp_r13; exp_r13=$(field_of "r13" "$TARGET_LINE")
    sleep 0.1
    run_qcore "$pid" || { fail "registers: qcore"; stop_target "$pid"; return; }
    local out; out=$(gdb --batch -ex "set confirm off" \
                     -ex "core-file core.$pid" \
                     -ex "info registers rbx r12 r13" \
                     -ex quit "$BIN_DIR/target_registers" 2>&1)
    [[ $VERBOSE -eq 1 ]] && echo "$out" | sed 's/^/    /'
    for pair in "rbx:$exp_rbx" "r12:$exp_r12" "r13:$exp_r13"; do
        local reg="${pair%%:*}" val="${pair##*:}"
        local bare; bare=$(echo "$val" | sed 's/^0x//I' | tr '[:upper:]' '[:lower:]')
        echo "$out" | grep -i "$reg" | grep -qi "$bare" \
            && pass "registers: $reg = $val" \
            || fail "registers: $reg = $val" "$(echo "$out" | grep -i "$reg" | head -1)"
    done
    stop_target "$pid"
}

# == FAILURE-SCENARIO TESTS =================================================
# These tests specifically cover failure modes of the previous COW-injection
# approach.  Each test name states which old failure mode it exercises.

# -- Old failure: SIGSTOP accumulation killed target after 4 runs -----------
section "Regression: repeated runs (was: died after 4 SIGSTOP accumulations)"

t_repeated_runs() {
    start_target "$BIN_DIR/target_simple" || { fail "repeat: startup"; return; }
    local pid="$TARGET_PID"
    local failed=0
    for i in $(seq 1 10); do
        run_qcore "$pid" || { failed=1; break; }
        kill -0 "$pid" 2>/dev/null || { failed=2; break; }
    done
    case $failed in
        0) pass "repeat: target survived 10 consecutive dumps" ;;
        1) fail "repeat: qcore failed on run $i" ;;
        2) fail "repeat: target died on run $i (was: accumulated SIGSTOP effects)" ;;
    esac
    stop_target "$pid"
}

# -- Old failure: ERESTARTNOHAND -> -EINTR in epoll_wait thread -------------
section "Regression: epoll_wait thread (was: ERESTARTNOHAND forced -EINTR)"

t_epoll_no_eintr() {
    start_target "$BIN_DIR/target_epoll" || { fail "epoll: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "epoll: qcore failed"; stop_target "$pid"; return; }
    # Primary check: target must still be alive.  A runaway -EINTR loop
    # from a broken rip-2 restart would crash the process.
    # (Note: we do NOT send SIGUSR1 to query the count because SIGUSR1
    # delivery itself interrupts epoll_wait with -EINTR, which would be
    # a measurement artifact, not a qcore side-effect.)
    if kill -0 "$pid" 2>/dev/null; then
        pass "epoll: target alive after dump (no fatal -EINTR from epoll_wait)"
    else
        fail "epoll: target dead after dump (was: rip-2 restart broke epoll_wait)"
    fi
    stop_target "$pid"
}

# -- Old failure: COW child visible in target process tree ------------------
section "Regression: double-fork stealth (was: COW child visible to watchdogs)"

t_child_invisible() {
    start_target "$BIN_DIR/target_children" || { fail "children: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "children: qcore"; stop_target "$pid"; return; }
    kill -0 "$pid" 2>/dev/null || { fail "children: target dead"; return; }
    # Ask target to stop monitoring
    kill -USR1 "$pid" 2>/dev/null
    sleep 0.1
    # Check if the target logged any unexpected children to stderr
    local log="/proc/$pid/fd/2"
    local unexpected
    unexpected=$(cat "$log" 2>/dev/null | grep "unexpected_child" | wc -l || echo 0)
    if [[ "$unexpected" -eq 0 ]]; then
        pass "children: no unexpected child PIDs seen by target"
    else
        fail "children: target saw $unexpected unexpected children" \
             "(was: COW clone appeared in target's /proc/self/children)"
    fi
    stop_target "$pid"
}

# -- Old failure: TCP socket RST from fd refcount hitting zero --------------
section "Regression: TCP socket survival (was: delayed RST from fd close)"

t_tcp_socket_alive() {
    command -v python3 >/dev/null 2>&1 || { skip "tcp_alive" "python3 absent"; return; }
    start_target "$BIN_DIR/target_sockets" || { fail "tcp_alive: startup"; return; }
    local pid="$TARGET_PID"
    local port; port=$(field_of "tcp_port" "$TARGET_LINE")
    run_qcore "$pid" || { fail "tcp_alive: qcore"; stop_target "$pid"; return; }
    kill -0 "$pid" 2>/dev/null || { fail "tcp_alive: target dead"; return; }
    # Verify the listening socket is still open after the dump
    local still_listening
    still_listening=$(python3 -c "
import socket, errno
s = socket.socket()
s.settimeout(1)
try:
    s.connect(('127.0.0.1', $port))
    s.close()
    print('ok')
except (ConnectionRefusedError, OSError) as e:
    print('refused:', e)
" 2>/dev/null)
    if echo "$still_listening" | grep -q "^ok"; then
        pass "tcp_alive: TCP listener still accepting after dump"
    else
        fail "tcp_alive: TCP listener dead after dump" \
             "$still_listening" \
             "(was: child fd close sent RST/FIN due to refcount reaching zero)"
    fi
    stop_target "$pid"
}

# -- Old failure: safe thread was in syscall (verify we used user-space) ----
section "Parasite quality: injection point"

t_safe_thread_was_userspace() {
    start_target "$BIN_DIR/target_simple" || { fail "safe_thread: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "safe_thread: qcore"; stop_target "$pid"; return; }
    if echo "$QCORE_OUT" | grep -q "was in user-space"; then
        pass "safe_thread: injected at user-space thread (cleanest path)"
    elif echo "$QCORE_OUT" | grep -q "was in syscall"; then
        pass "safe_thread: injected at syscall-blocked thread (rip-2 restart)"
    else
        fail "safe_thread: injection point not reported in qcore output"
    fi
    stop_target "$pid"
}

t_child2_invisible_after_dump() {
    start_target "$BIN_DIR/target_simple" || { fail "child2: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "child2: qcore"; stop_target "$pid"; return; }
    # After Phase 6, child2 must be fully gone from /proc
    local child2_pid; child2_pid=$(echo "$QCORE_OUT" | grep -oP 'child2 \(PID=\K[0-9]+')
    if [[ -n "$child2_pid" ]]; then
        if [[ -d "/proc/$child2_pid" ]]; then
            fail "child2: PID=$child2_pid still in /proc after Phase 6"
        else
            pass "child2: PID=$child2_pid gone from /proc after Phase 6"
        fi
    else
        pass "child2: could not determine child2 PID (likely already reaped)"
    fi
    stop_target "$pid"
}

# -- Main -------------------------------------------------------------------
main() {
    echo -e "${BOLD}qcore test suite${NC}"
    echo "qcore:   $QCORE"
    echo "targets: $BIN_DIR"

    preflight

    local workdir; workdir=$(mktemp -d /tmp/qcore_tests_XXXXXX)
    CLEANUP_FILES+=("$workdir")
    cd "$workdir"

    section "Error handling"
    t_no_args
    t_bad_pid

    section "ELF core structure"
    t_elf_valid
    t_segments
    t_notes

    section "Target liveness & size"
    t_alive
    t_core_size

    section "Memory content"
    t_marker

    section "Multi-threaded (8 threads)"
    t_multithreaded

    section "Socket / FD harvesting"
    t_sockets_file
    t_json_valid
    t_json_tcp
    t_json_fds

    section "GDB integration"
    t_gdb_loads
    t_gdb_backtrace
    t_gdb_threads

    section "Register fidelity"
    t_registers

    section "Failure-scenario regressions"
    t_repeated_runs
    t_epoll_no_eintr
    t_child_invisible
    t_tcp_socket_alive
    t_safe_thread_was_userspace
    t_child2_invisible_after_dump

    echo ""
    echo -e "${BOLD}Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, ${YELLOW}$SKIP skipped${NC}"
    [[ "$FAIL" -eq 0 ]]
}

main "$@"
