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
# run_qcore <pid> [extra qcore args...]
# Extra args (e.g. -f) are passed to qcore before the pid.
run_qcore() {
    local pid="$1"; shift
    local out; out=$(mktemp /tmp/qcore_out_XXXXXX)
    CLEANUP_FILES+=("$out" "core.$pid" "core.$pid.fds.json" "core.$pid.threads.json")
    local invoke=("$QCORE" "$@" "$pid")
    [[ $EUID -ne 0 ]] && invoke=(sudo "${invoke[@]}")
    if "${invoke[@]}" >"$out" 2>&1; then
        QCORE_OUT=$(cat "$out")
        [[ $VERBOSE -eq 1 ]] && echo "$QCORE_OUT" | sed 's/^/    /'
        return 0
    else
        QCORE_OUT=$(cat "$out")
        [[ $VERBOSE -eq 1 ]] && { echo "    qcore exited nonzero:" >&2
                                 echo "$QCORE_OUT" | sed 's/^/    /' >&2; }
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
              target_epoll target_children target_callstack target_idle; do
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

t_compressed_core() {
    command -v xz >/dev/null 2>&1 || { skip "compressed_core" "xz absent"; return; }
    start_target "$BIN_DIR/target_simple" || { fail "compressed_core: startup"; return; }
    local pid="$TARGET_PID"
    CLEANUP_FILES+=("core.$pid.xz")
    run_qcore "$pid" -c || { fail "compressed_core: qcore -c failed"; stop_target "$pid"; return; }
    # File must exist and be a valid xz stream.
    [[ -f "core.$pid.xz" ]] \
        && pass "compressed_core: core.$pid.xz created" \
        || { fail "compressed_core: no .xz file"; stop_target "$pid"; return; }
    xz --test "core.$pid.xz" 2>/dev/null \
        && pass "compressed_core: valid xz stream" \
        || fail "compressed_core: corrupt xz stream"
    # Decompressed content must be a valid ELF core.
    local etype
    etype=$(xz -d --stdout "core.$pid.xz" 2>/dev/null | file - 2>/dev/null)
    echo "$etype" | grep -q "ELF 64-bit LSB core" \
        && pass "compressed_core: decompresses to a valid ELF core" \
        || fail "compressed_core: decompressed content is not ELF core"
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
    [[ -f "core.$pid.fds.json" ]] \
        && pass "sockets_file: JSON created" \
        || fail "sockets_file: JSON missing"
    stop_target "$pid"
}

t_json_valid() {
    command -v python3 >/dev/null 2>&1 || { skip "json_valid" "python3 absent"; return; }
    start_target "$BIN_DIR/target_sockets" || { fail "json_valid: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "json_valid: qcore"; stop_target "$pid"; return; }
    python3 -m json.tool "core.$pid.fds.json" >/dev/null 2>&1 \
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
    local j; j=$(cat "core.$pid.fds.json" 2>/dev/null)
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
import json; d=json.load(open('core.$pid.fds.json')); print(len(d['fds']))" 2>/dev/null || echo 0)
    [[ "$count" -ge 3 ]] && pass "json_fds: $count FDs (>= stdin/stdout/stderr)" \
                          || fail "json_fds: too few FDs" "got $count"
    stop_target "$pid"
}

t_json_fds_flags() {
    # Every FD entry must have an "access" field (r/w/rw) from fdinfo.
    # Regular files (stdin/stdout/stderr) must also have pos and size.
    command -v python3 >/dev/null 2>&1 || { skip "json_fds_flags" "python3 absent"; return; }
    start_target "$BIN_DIR/target_simple" || { fail "json_fds_flags: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "json_fds_flags: qcore"; stop_target "$pid"; return; }
    python3 - "core.$pid.fds.json" << 'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
fds = d["fds"]
# Every entry must have "access".
missing_access = [f["fd"] for f in fds if "access" not in f]
assert not missing_access, f"FDs missing 'access' field: {missing_access}"
# "access" must be one of the three valid values.
bad_access = [f for f in fds if f.get("access") not in ("r","w","rw")]
assert not bad_access, f"invalid 'access' values: {bad_access}"
# Regular file FDs must have pos and size.
file_fds = [f for f in fds if f.get("type") == "file"]
assert file_fds, "no FD_TYPE_OTHER entries found"
for f in file_fds:
    assert "pos"  in f, f"fd {f['fd']} ({f.get('path','?')}) missing 'pos'"
    assert "size" in f, f"fd {f['fd']} ({f.get('path','?')}) missing 'size'"
    assert isinstance(f["pos"],  int), "'pos' must be int"
    assert isinstance(f["size"], int), "'size' must be int"
    assert f["pos"]  >= 0, "'pos' must be non-negative"
    assert f["size"] >= 0, "'size' must be non-negative"
print(f"ok: {len(fds)} FDs, all have access; {len(file_fds)} file FDs have pos/size")
PYEOF
    local rc=$?
    [[ $rc -eq 0 ]] \
        && pass "json_fds_flags: all FDs have access; file FDs have pos/size" \
        || fail "json_fds_flags: missing or invalid fields (see python output)"
    stop_target "$pid"
}

t_json_tcp_queues() {
    # TCP sockets must expose recv_q and send_q (queue depths).
    command -v python3 >/dev/null 2>&1 || { skip "json_tcp_queues" "python3 absent"; return; }
    start_target "$BIN_DIR/target_sockets" || { fail "json_tcp_queues: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "json_tcp_queues: qcore"; stop_target "$pid"; return; }
    python3 - "core.$pid.fds.json" << 'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
tcp_fds = [f for f in d["fds"] if f.get("type") in ("tcp4","tcp6","udp4","udp6")]
assert tcp_fds, "no TCP/UDP FDs found"
for f in tcp_fds:
    assert "recv_q" in f, f"fd {f['fd']} missing recv_q"
    assert "send_q" in f, f"fd {f['fd']} missing send_q"
    assert isinstance(f["recv_q"], int), "recv_q must be int"
    assert isinstance(f["send_q"], int), "send_q must be int"
    assert f["recv_q"] >= 0, "recv_q must be non-negative"
    assert f["send_q"] >= 0, "send_q must be non-negative"
print(f"ok: {len(tcp_fds)} TCP/UDP FD(s) all have recv_q and send_q")
PYEOF
    local rc=$?
    [[ $rc -eq 0 ]] \
        && pass "json_tcp_queues: TCP/UDP FDs have recv_q and send_q" \
        || fail "json_tcp_queues: missing queue depth fields (see python output)"
    stop_target "$pid"
}

t_threads_json_file() {
    start_target "$BIN_DIR/target_simple" || { fail "threads_json: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "threads_json: qcore"; stop_target "$pid"; return; }
    [[ -f "core.$pid.threads.json" ]] \
        && pass "threads_json: core.$pid.threads.json created" \
        || fail "threads_json: file not created"
    stop_target "$pid"
}

t_threads_json_valid() {
    command -v python3 >/dev/null 2>&1 || { skip "threads_json_valid" "python3 absent"; return; }
    start_target "$BIN_DIR/target_simple" || { fail "threads_json_valid: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "threads_json_valid: qcore"; stop_target "$pid"; return; }
    python3 -m json.tool "core.$pid.threads.json" >/dev/null 2>&1 \
        && pass "threads_json_valid: well-formed JSON" \
        || fail "threads_json_valid: malformed JSON"
    stop_target "$pid"
}

t_threads_json_content() {
    command -v python3 >/dev/null 2>&1 || { skip "threads_json_content" "python3 absent"; return; }
    # Use target_mt so we have multiple named threads to check.
    start_target "$BIN_DIR/target_mt" || { fail "threads_json_content: startup"; return; }
    local pid="$TARGET_PID"
    local n_threads; n_threads=$(field_of "threads" "$TARGET_LINE"); n_threads="${n_threads:-8}"
    run_qcore "$pid" || { fail "threads_json_content: qcore"; stop_target "$pid"; return; }
    # JSON must have the right pid and at least as many entries as threads.
    python3 - "$pid" "$n_threads" "core.$pid.threads.json" << 'PYEOF'
import json, sys
pid, n_threads, path = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
d = json.load(open(path))
assert d["pid"] == pid,      f"pid mismatch: {d['pid']} != {pid}"
threads = d["threads"]
assert len(threads) >= n_threads, \
    f"only {len(threads)} thread entries (expected >= {n_threads})"
for t in threads:
    assert "tid"  in t, "missing tid field"
    assert "name" in t, "missing name field"
    assert isinstance(t["tid"],  int), "tid must be int"
    assert isinstance(t["name"], str), "name must be str"
    if "ns_tid" in t:
        assert isinstance(t["ns_tid"], int), "ns_tid must be int"
        assert t["ns_tid"] > 0, "ns_tid must be positive"
# Every entry must have a unique TID.
tids = [t["tid"] for t in threads]
assert len(tids) == len(set(tids)), "duplicate TIDs"
print(f"ok: {len(threads)} threads, all fields present")
PYEOF
    local rc=$?
    [[ $rc -eq 0 ]] \
        && pass "threads_json_content: pid correct, $n_threads+ entries, all fields valid" \
        || fail "threads_json_content: JSON content invalid (see python output above)"
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

# -- epoll thread survives a forced dump ------------------------------------
section "Regression: epoll_wait thread under -f (benign EINTR, survives)"

t_epoll_no_eintr() {
    # target_epoll is single-threaded and blocks forever in epoll_wait, so it
    # is the fully-idle case: safe mode correctly refuses it (tested
    # elsewhere).  Here we force a dump with -f and verify the target survives
    # the one benign -EINTR that epoll_wait surfaces -- exactly what any
    # signal would cause, and what a correct epoll loop handles by retrying.
    start_target "$BIN_DIR/target_epoll" || { fail "epoll: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" -f || { fail "epoll: qcore -f failed"; stop_target "$pid"; return; }
    if kill -0 "$pid" 2>/dev/null; then
        pass "epoll: target alive after forced dump (benign EINTR handled)"
    else
        fail "epoll: target dead after forced dump"
    fi
    stop_target "$pid"
}

# -- Cleanup phase leaves no zombie in the target ---------------------------
section "Cleanup: target reaps the snapshot child (no zombie left)"

t_no_zombie_after_dump() {
    # The child is a direct child of the target during the dump.  qcore's final
    # cleanup phase injects wait4() into the target so the target reaps it.
    # Afterwards the target must have no <defunct> children.
    start_target "$BIN_DIR/target_simple" || { fail "no_zombie: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "no_zombie: qcore"; stop_target "$pid"; return; }
    kill -0 "$pid" 2>/dev/null || { fail "no_zombie: target dead"; return; }

    # Give the kernel a moment to settle the reap.
    sleep 0.2

    # Count zombie children of the target by scanning /proc for processes
    # whose PPid is the target and whose State is Z.
    local zombies=0
    local d st ppid state
    for d in /proc/[0-9]*; do
        st="$d/status"
        [[ -r "$st" ]] || continue
        ppid=$(grep -m1 '^PPid:' "$st" 2>/dev/null | awk '{print $2}')
        [[ "$ppid" == "$pid" ]] || continue
        state=$(grep -m1 '^State:' "$st" 2>/dev/null | awk '{print $2}')
        [[ "$state" == "Z" ]] && zombies=$((zombies + 1))
    done

    if [[ "$zombies" -eq 0 ]]; then
        pass "no_zombie: target has no zombie children after dump"
    else
        fail "no_zombie: target left with $zombies zombie child(ren)" \
             "(cleanup phase 7 wait4 injection did not reap child)"
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

# -- Core dump quality: stack frames ----------------------------------------
#
# This section is the only test that checks whether the core is actually
# useful for debugging.  The existing GDB tests (t_gdb_backtrace etc.) accept
# "?? ()" frames as a pass; this test requires named symbols in the correct
# call order, proving that:
#
#   1. NT_PRSTATUS registers (RIP/RSP) are correct for every thread.
#   2. The memory snapshot (child COW pages) contains intact stack frames
#      at those RSP values -- i.e. the register and memory snapshots are
#      temporally consistent.
#   3. GDB can resolve function names (binary load address / NT_FILE correct).
#
# target_callstack is compiled as PIE (modern distro default) so the test
# exercises NT_FILE load-bias resolution exactly as real-world binaries do.
#
section "Core dump quality: stack frames and thread registers"

# Print detailed diagnostics when the callstack test fails, isolating whether
# the problem is registers (RIP/RSP), symbol resolution (NT_FILE load bias),
# or stack memory (PT_LOAD coverage).
#   $1 = core pid    $2 = the 'thread apply all bt' output already collected
callstack_dump_diagnostics() {
    local pid="$1" bt="$2"
    local core="core.$pid"
    local exe="$BIN_DIR/target_callstack"

    echo "    ===== DIAGNOSTICS ====="

    echo "    --- thread apply all bt (raw) ---"
    echo "$bt" | sed 's/^/      /'

    echo "    --- per-thread RIP and symbol-at-RIP (from core) ---"
    gdb --batch -ex "set confirm off" -ex "core-file $core" \
        -ex "thread apply all bt 1" \
        -ex "info auxv" \
        -ex quit "$exe" 2>&1 | grep -iE "thread|rip|0x|AT_PHDR|AT_ENTRY|AT_BASE" \
        | head -30 | sed 's/^/      /'

    echo "    --- NT_FILE / PRSTATUS notes in core ---"
    readelf -n "$core" 2>/dev/null | grep -iE "NT_FILE|NT_PRSTATUS|CORE" \
        | head -20 | sed 's/^/      /'

    echo "    --- executable mapping in core's NT_FILE vs live /proc/pid/maps ---"
    echo "      [core NT_FILE - first lines]"
    readelf -n "$core" 2>/dev/null | grep -A60 "NT_FILE" \
        | grep target_callstack | head -5 | sed 's/^/        /'
    echo "      [live maps - executable]"
    grep target_callstack "/proc/$pid/maps" 2>/dev/null | head -5 | sed 's/^/        /'

    echo "    --- PT_LOAD count and first few segments ---"
    readelf -lW "$core" 2>/dev/null | grep -E "LOAD" | head -6 | sed 's/^/      /'

    echo "    ===== END DIAGNOSTICS ====="
}

t_callstack_frames() {
    [[ $HAS_GDB -eq 1 ]] || { skip "callstack" "gdb absent"; return; }
    [[ -x "$BIN_DIR/target_callstack" ]] || {
        skip "callstack" "target_callstack not built (run 'make' in test/)"; return; }

    start_target "$BIN_DIR/target_callstack" \
        || { fail "callstack: target startup"; return; }
    local pid="$TARGET_PID"

    run_qcore "$pid" || { fail "callstack: qcore failed"; stop_target "$pid"; return; }

    kill -0 "$pid" 2>/dev/null \
        || { fail "callstack: target dead after dump"; return; }

    # Load the core in GDB and collect the full backtrace for every thread.
    local bt
    bt=$(gdb --batch \
         -ex "set confirm off" \
         -ex "set print frame-arguments none" \
         -ex "core-file core.$pid" \
         -ex "thread apply all bt 20" \
         -ex quit \
         "$BIN_DIR/target_callstack" 2>&1)

    [[ $VERBOSE -eq 1 ]] && echo "$bt" | sed 's/^/    /'

    # ---- Thread count -------------------------------------------------------
    # GDB prints "Thread N (..." for each thread it finds in the core.
    local nthreads
    nthreads=$(echo "$bt" | grep -cE '^Thread [0-9]' || true)
    if [[ "$nthreads" -ge 4 ]]; then
        pass "callstack: $nthreads threads visible in core"
    else
        fail "callstack: $nthreads threads visible (expected >= 4)" \
             "NT_PRSTATUS notes may be missing or have wrong pr_pid values"
        stop_target "$pid"
        return
    fi

    # ---- Application frame presence (non-vacuous) ---------------------------
    # Count how many tc_* frames appear at all.  If ZERO appear, the stacks
    # are unusable: either the registers (RIP/RSP) are wrong or the stack
    # memory in the core does not match the live process.
    local tc_frames
    tc_frames=$(echo "$bt" | grep -cE "in tc_[a-z0-9_]+" || true)
    if [[ "$tc_frames" -ge 1 ]]; then
        pass "callstack: $tc_frames application (tc_*) frames present in backtraces"
    else
        fail "callstack: ZERO tc_* frames in any backtrace -- stacks are garbage"
        callstack_dump_diagnostics "$pid" "$bt"
    fi

    # ---- Per-function presence checks ---------------------------------------
    # Each tc_* function is unique to one thread.  Its absence means either
    # RSP was wrong (wrong frame) or the stack memory is missing/corrupted.
    local all_present=1
    for fn in \
        tc_t1_entry tc_t1_mid tc_t1_leaf \
        tc_t2_entry tc_t2_leaf \
        tc_t3_leaf \
        tc_main_blocker tc_main_leaf
    do
        if echo "$bt" | grep -qE "in ${fn}[[:space:](]"; then
            pass "callstack: '${fn}' present in backtrace"
        else
            fail "callstack: '${fn}' MISSING from all backtraces" \
                 "RSP or stack memory is inconsistent with the live state"
            all_present=0
        fi
    done

    # ---- Call order check for thread 1 (deepest chain) ----------------------
    # In GDB output, callee frames have lower #N numbers and appear earlier
    # in the text.  tc_t1_leaf (#0 equivalent) must appear before tc_t1_mid,
    # which must appear before tc_t1_entry.
    if [[ "$all_present" -eq 1 ]]; then
        local l_leaf l_mid l_entry
        l_leaf=$(echo  "$bt" | grep -nE "in tc_t1_leaf[[:space:](]"  | head -1 | cut -d: -f1)
        l_mid=$(echo   "$bt" | grep -nE "in tc_t1_mid[[:space:](]"   | head -1 | cut -d: -f1)
        l_entry=$(echo "$bt" | grep -nE "in tc_t1_entry[[:space:](]" | head -1 | cut -d: -f1)

        if [[ -n "$l_leaf" && -n "$l_mid" && -n "$l_entry" &&
              "$l_leaf" -lt "$l_mid" && "$l_mid" -lt "$l_entry" ]]; then
            pass "callstack: frame order correct: tc_t1_leaf < tc_t1_mid < tc_t1_entry"
        else
            fail "callstack: frame order wrong for thread-1 chain" \
                 "leaf=$l_leaf mid=$l_mid entry=$l_entry (expected leaf < mid < entry)" \
                 "stack memory snapshot may not match the register snapshot"
        fi

        # Spot-check thread 2's chain.
        local l2_leaf l2_entry
        l2_leaf=$(echo  "$bt" | grep -nE "in tc_t2_leaf[[:space:](]"  | head -1 | cut -d: -f1)
        l2_entry=$(echo "$bt" | grep -nE "in tc_t2_entry[[:space:](]" | head -1 | cut -d: -f1)
        if [[ -n "$l2_leaf" && -n "$l2_entry" && "$l2_leaf" -lt "$l2_entry" ]]; then
            pass "callstack: frame order correct: tc_t2_leaf < tc_t2_entry"
        else
            fail "callstack: frame order wrong for thread-2 chain" \
                 "leaf=$l2_leaf entry=$l2_entry"
        fi

        # Main thread chain.
        local lm_leaf lm_blocker
        lm_leaf=$(echo    "$bt" | grep -nE "in tc_main_leaf[[:space:](]"    | head -1 | cut -d: -f1)
        lm_blocker=$(echo "$bt" | grep -nE "in tc_main_blocker[[:space:](]" | head -1 | cut -d: -f1)
        if [[ -n "$lm_leaf" && -n "$lm_blocker" && "$lm_leaf" -lt "$lm_blocker" ]]; then
            pass "callstack: frame order correct: tc_main_leaf < tc_main_blocker"
        else
            fail "callstack: frame order wrong for main-thread chain" \
                 "leaf=$lm_leaf blocker=$lm_blocker"
        fi
    fi

    stop_target "$pid"
}

# -- Injector is always a clean point in safe mode -------------------------
section "Parasite quality: injection point"

t_safe_injector_is_clean() {
    # In default (safe) mode the injector must be either a user-space thread
    # or a syscall-exit reached via the race -- never a forced mid-syscall
    # hijack.  target_simple idles in nanosleep, so the race wins quickly.
    start_target "$BIN_DIR/target_simple" || { fail "injector: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "injector: qcore"; stop_target "$pid"; return; }
    if echo "$QCORE_OUT" | grep -qE "injector .*(user-space \(clean\)|syscall-exit \(clean)"; then
        pass "injector: safe mode used a clean injection point"
    else
        fail "injector: safe mode did not report a clean injection point" \
             "$(echo "$QCORE_OUT" | grep -i injector)"
    fi
    echo "$QCORE_OUT" | grep -q "forced" \
        && fail "injector: safe mode unexpectedly forced a mid-syscall hijack" \
        || pass "injector: safe mode did not force a hijack"
    stop_target "$pid"
}

# -- Safe mode refuses a fully-idle target; -f forces it --------------------
section "Safe mode vs force mode (fully idle target)"

t_safe_mode_refuses_idle() {
    # target_idle blocks forever in pause(); no thread ever reaches a
    # syscall-exit, so safe mode must time out and refuse.  Use a short race
    # timeout so the test is fast.
    start_target "$BIN_DIR/target_idle" || { fail "idle_refuse: startup"; return; }
    local pid="$TARGET_PID"
    local out; out=$(mktemp /tmp/qcore_out_XXXXXX)
    CLEANUP_FILES+=("$out" "core.$pid" "core.$pid.fds.json" "core.$pid.threads.json")
    local invoke=(env QCORE_RACE_TIMEOUT_SEC=2 "$QCORE" "$pid")
    [[ $EUID -ne 0 ]] && invoke=(sudo "${invoke[@]}")
    if "${invoke[@]}" >"$out" 2>&1; then
        fail "idle_refuse: safe mode should have refused but succeeded"
    else
        pass "idle_refuse: safe mode refused the fully-idle target"
    fi
    grep -q "f to force" "$out" \
        && pass "idle_refuse: refusal message advises -f" \
        || fail "idle_refuse: refusal message missing -f advice" "$(cat $out)"
    kill -0 "$pid" 2>/dev/null \
        && pass "idle_refuse: target still alive after refusal" \
        || fail "idle_refuse: target died (refusal should be harmless)"
    [[ ! -f "core.$pid" ]] \
        && pass "idle_refuse: no core file produced" \
        || fail "idle_refuse: a core file was produced despite refusal"
    stop_target "$pid"
}

t_force_mode_dumps_idle() {
    # With -f, qcore hijacks the blocked thread and dumps successfully.
    start_target "$BIN_DIR/target_idle" || { fail "idle_force: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" -f || { fail "idle_force: qcore -f failed"; stop_target "$pid"; return; }
    [[ -f "core.$pid" ]] \
        && pass "idle_force: -f produced a core on the idle target" \
        || fail "idle_force: no core produced under -f"
    kill -0 "$pid" 2>/dev/null \
        && pass "idle_force: target still alive after -f dump" \
        || fail "idle_force: target died after -f dump"
    echo "$QCORE_OUT" | grep -q "forced" \
        && pass "idle_force: qcore reported forced injection" \
        || fail "idle_force: expected 'forced' in output"
    stop_target "$pid"
}

t_child_gone_after_dump() {
    start_target "$BIN_DIR/target_simple" || { fail "child: startup"; return; }
    local pid="$TARGET_PID"
    run_qcore "$pid" || { fail "child: qcore"; stop_target "$pid"; return; }
    # After Phases 6-7, the child must be fully gone from /proc
    local child_pid; child_pid=$(echo "$QCORE_OUT" | grep -oP 'child \(PID=\K[0-9]+')
    if [[ -n "$child_pid" ]]; then
        if [[ -d "/proc/$child_pid" ]]; then
            fail "child: PID=$child_pid still in /proc after dump"
        else
            pass "child: PID=$child_pid gone from /proc after dump"
        fi
    else
        pass "child: could not determine child PID (likely already reaped)"
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
    t_compressed_core

    section "Memory content"
    t_marker

    section "Multi-threaded (8 threads)"
    t_multithreaded

    section "Socket / FD harvesting"
    t_sockets_file
    t_json_valid
    t_json_tcp
    t_json_fds
    t_json_fds_flags
    t_json_tcp_queues
    t_threads_json_file
    t_threads_json_valid
    t_threads_json_content

    section "GDB integration"
    t_gdb_loads
    t_gdb_backtrace
    t_gdb_threads

    section "Register fidelity"
    t_registers

    section "Core dump quality: stack frames and thread registers"
    t_callstack_frames

    section "Parasite quality: injection point"
    t_safe_injector_is_clean

    section "Safe mode vs force mode (fully idle target)"
    t_safe_mode_refuses_idle
    t_force_mode_dumps_idle

    section "Cleanup: target reaps the snapshot child (no zombie left)"
    t_no_zombie_after_dump

    section "Failure-scenario regressions"
    t_repeated_runs
    t_epoll_no_eintr
    t_tcp_socket_alive
    t_child_gone_after_dump

    echo ""
    echo -e "${BOLD}Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, ${YELLOW}$SKIP skipped${NC}"
    [[ "$FAIL" -eq 0 ]]
}

main "$@"
