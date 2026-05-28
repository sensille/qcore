#!/usr/bin/env bash
# qcore test suite
#
# Usage: ./run_tests.sh [-v]
#   -v  verbose: show qcore and gdb output even on passing tests
#
# Requirements:
#   - Must be run from the test/ directory (or any directory adjacent to qcore)
#   - sudo must work without a password prompt (or run as root)
#   - readelf, file, strings must be in PATH
#   - gdb is optional; register/backtrace tests are skipped if absent
#   - python3 is optional; JSON validity test is skipped if absent

set -u

# -- Locate binaries --------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
QCORE="$SCRIPT_DIR/../qcore"
BIN_DIR="$SCRIPT_DIR"

VERBOSE=0
[[ "${1:-}" == "-v" ]] && VERBOSE=1

# -- Counters and colour ----------------------------------------------------
PASS=0; FAIL=0; SKIP=0
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)) || true; }
fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    shift
    for msg in "$@"; do echo "         $msg"; done
    ((FAIL++)) || true
}
skip() { echo -e "${YELLOW}[SKIP]${NC} $1  (${2})"; ((SKIP++)) || true; }
section() { echo -e "\n${BOLD}-- $1 --${NC}"; }

# -- Cleanup ----------------------------------------------------------------
CLEANUP_PIDS=()
CLEANUP_FILES=()

cleanup() {
    for p in "${CLEANUP_PIDS[@]:-}"; do
        kill "$p" 2>/dev/null || true
    done
    for f in "${CLEANUP_FILES[@]:-}"; do
        rm -rf "$f"
    done
    rm -f /tmp/qcore_test_*.sock
}
trap cleanup EXIT

# -- Helpers ----------------------------------------------------------------

# Start a target binary, capture its "ready ..." stdout line, return PID.
# Usage: start_target <binary> [args...]
# Sets globals: TARGET_PID, TARGET_LINE
start_target() {
    local bin="$1"; shift
    local outfile
    outfile=$(mktemp /tmp/qcore_target_XXXXXX)
    CLEANUP_FILES+=("$outfile")

    "$bin" "$@" >"$outfile" 2>/dev/null &
    local pid=$!
    CLEANUP_PIDS+=("$pid")

    # Wait up to 3 s for the target to print its "ready" line
    local i=0
    while [[ $i -lt 60 ]]; do
        if [[ -s "$outfile" ]]; then
            TARGET_LINE=$(cat "$outfile")
            TARGET_PID="$pid"
            return 0
        fi
        sleep 0.05
        ((i++)) || true
    done
    echo "  timeout waiting for $bin to print ready line" >&2
    TARGET_PID="$pid"
    TARGET_LINE=""
    return 1
}

# Extract a field from the target's "ready" line.
# Usage: field_of "key" "$TARGET_LINE"
field_of() {
    echo "$2" | grep -oP "(?<=$1=)\S+"
}

# Run qcore on $1 (PID), using sudo only when not already root.
QCORE_OUT=""
run_qcore() {
    local pid="$1"
    local outfile
    outfile=$(mktemp /tmp/qcore_out_XXXXXX)
    CLEANUP_FILES+=("$outfile")
    CLEANUP_FILES+=("core.$pid" "core.$pid.sockets.json")

    local invoke=("$QCORE" "$pid")
    [[ $EUID -ne 0 ]] && invoke=(sudo "${invoke[@]}")

    if "${invoke[@]}" >"$outfile" 2>&1; then
        QCORE_OUT=$(cat "$outfile")
        [[ $VERBOSE -eq 1 ]] && echo "$QCORE_OUT" | sed 's/^/    /'
        return 0
    else
        QCORE_OUT=$(cat "$outfile")
        echo "    qcore failed:" >&2
        echo "$QCORE_OUT" | sed 's/^/    /' >&2
        return 1
    fi
}

# Kill a target and remove it from CLEANUP_PIDS.
stop_target() {
    local pid="$1"
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    CLEANUP_PIDS=("${CLEANUP_PIDS[@]/$pid}")
}

# -- Pre-flight -------------------------------------------------------------
preflight() {
    local ok=1

    [[ -x "$QCORE" ]] || { echo "qcore binary not found at $QCORE - run 'make' first"; ok=0; }

    for t in target_simple target_mt target_sockets target_registers; do
        [[ -x "$BIN_DIR/$t" ]] || {
            echo "Missing test binary: $BIN_DIR/$t - run 'make' in test/ first"
            ok=0
        }
    done

    for cmd in readelf file strings; do
        command -v "$cmd" >/dev/null 2>&1 || { echo "Missing required tool: $cmd"; ok=0; }
    done

    # Verify we have ptrace privileges (root or passwordless sudo)
    if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
        echo "Need root or passwordless sudo - run as: sudo bash run_tests.sh"
        ok=0
    fi

    [[ $ok -eq 1 ]] || exit 1
}

# -- Error-handling tests (no target needed) --------------------------------
section "Error handling"

t_no_args() {
    local out
    out=$("$QCORE" 2>&1) || true
    if echo "$out" | grep -qi "usage\|pid"; then
        pass "no_args: prints usage"
    else
        fail "no_args: prints usage" "expected usage message, got: $out"
    fi
    if "$QCORE" 2>/dev/null; then
        fail "no_args: exits nonzero"
    else
        pass "no_args: exits nonzero"
    fi
}

t_bad_pid() {
    local out
    if out=$(sudo "$QCORE" 9999999 2>&1); then
        fail "bad_pid: exits nonzero"
    else
        pass "bad_pid: exits nonzero"
    fi
    if echo "$out" | grep -qiE "not found|no such|invalid|error"; then
        pass "bad_pid: informative error message"
    else
        fail "bad_pid: informative error message" "got: $out"
    fi
}

# -- ELF structure tests ----------------------------------------------------
section "ELF core structure (single-threaded target)"

t_elf_valid() {
    start_target "$BIN_DIR/target_simple" || { fail "elf_valid: target startup"; return; }
    local pid="$TARGET_PID"

    run_qcore "$pid" || { fail "elf_valid: qcore failed"; stop_target "$pid"; return; }

    if file "core.$pid" 2>/dev/null | grep -q "ELF 64-bit LSB core file"; then
        pass "elf_valid: file(1) reports ELF 64-bit core"
    else
        fail "elf_valid: file(1) reports ELF 64-bit core" \
             "got: $(file "core.$pid" 2>/dev/null)"
    fi

    local etype
    etype=$(readelf -h "core.$pid" 2>/dev/null | awk '/Type:/{print $2}')
    if [[ "$etype" == "CORE" ]]; then
        pass "elf_valid: ELF type is ET_CORE"
    else
        fail "elf_valid: ELF type is ET_CORE" "got: $etype"
    fi

    local mach
    mach=$(readelf -h "core.$pid" 2>/dev/null | grep "Machine:")
    if echo "$mach" | grep -q "X86-64\|Advanced Micro Devices X86-64"; then
        pass "elf_valid: machine is EM_X86_64"
    else
        fail "elf_valid: machine is EM_X86_64" "got: $mach"
    fi

    stop_target "$pid"
}

t_segments() {
    start_target "$BIN_DIR/target_simple" || { fail "segments: target startup"; return; }
    local pid="$TARGET_PID"

    run_qcore "$pid" || { fail "segments: qcore failed"; stop_target "$pid"; return; }

    # PT_NOTE must be present
    if readelf -l "core.$pid" 2>/dev/null | grep -q "NOTE"; then
        pass "segments: PT_NOTE present"
    else
        fail "segments: PT_NOTE present"
    fi

    # At least 5 PT_LOAD segments (any real process has many more)
    local nload
    nload=$(readelf -l "core.$pid" 2>/dev/null | grep -c "LOAD" || true)
    if [[ "$nload" -ge 5 ]]; then
        pass "segments: $nload PT_LOAD segments"
    else
        fail "segments: at least 5 PT_LOAD segments" "got $nload"
    fi

    stop_target "$pid"
}

t_notes() {
    start_target "$BIN_DIR/target_simple" || { fail "notes: target startup"; return; }
    local pid="$TARGET_PID"

    run_qcore "$pid" || { fail "notes: qcore failed"; stop_target "$pid"; return; }

    local notes
    notes=$(readelf -n "core.$pid" 2>/dev/null)

    if echo "$notes" | grep -q "NT_PRSTATUS"; then
        pass "notes: NT_PRSTATUS present"
    else
        fail "notes: NT_PRSTATUS present"
    fi

    if echo "$notes" | grep -q "NT_PRPSINFO"; then
        pass "notes: NT_PRPSINFO present"
    else
        fail "notes: NT_PRPSINFO present"
    fi

    if echo "$notes" | grep -q "NT_FILE"; then
        pass "notes: NT_FILE present"
    else
        fail "notes: NT_FILE present"
    fi

    stop_target "$pid"
}

# -- Target liveness --------------------------------------------------------
section "Target liveness"

t_target_alive() {
    start_target "$BIN_DIR/target_simple" || { fail "alive: target startup"; return; }
    local pid="$TARGET_PID"

    run_qcore "$pid" || { fail "alive: qcore failed"; stop_target "$pid"; return; }

    if kill -0 "$pid" 2>/dev/null; then
        pass "alive: target still running after dump"
    else
        fail "alive: target still running after dump" \
             "process $pid is dead - Phase 4 (restore/detach) likely broken"
    fi

    stop_target "$pid"
}

t_core_size() {
    start_target "$BIN_DIR/target_simple" || { fail "core_size: target startup"; return; }
    local pid="$TARGET_PID"

    run_qcore "$pid" || { fail "core_size: qcore failed"; stop_target "$pid"; return; }

    local size
    size=$(stat -c %s "core.$pid" 2>/dev/null || echo 0)
    if [[ "$size" -gt 65536 ]]; then
        pass "core_size: core is ${size} bytes (> 64 KB)"
    else
        fail "core_size: core > 64 KB" "actual size: $size bytes"
    fi

    stop_target "$pid"
}

# -- Memory content ---------------------------------------------------------
section "Memory content"

t_marker_string() {
    start_target "$BIN_DIR/target_simple" || { fail "marker: target startup"; return; }
    local pid="$TARGET_PID"

    run_qcore "$pid" || { fail "marker: qcore failed"; stop_target "$pid"; return; }

    if strings "core.$pid" 2>/dev/null | grep -q "QCORE_MEMORY_MARKER_DEADBEEF1234"; then
        pass "marker: known BSS string found in core memory"
    else
        fail "marker: known BSS string found in core memory" \
             "strings/grep found nothing - PT_LOAD data may be missing"
    fi

    stop_target "$pid"
}

# -- Multi-threaded ---------------------------------------------------------
section "Multi-threaded target (8 threads)"

t_multithreaded() {
    start_target "$BIN_DIR/target_mt" || { fail "mt: target startup"; return; }
    local pid="$TARGET_PID"
    local n_threads
    n_threads=$(field_of "threads" "$TARGET_LINE")
    n_threads="${n_threads:-8}"

    run_qcore "$pid" || { fail "mt: qcore failed"; stop_target "$pid"; return; }

    # Count NT_PRSTATUS occurrences - one per thread
    local n_prstatus
    n_prstatus=$(readelf -n "core.$pid" 2>/dev/null | grep -c "NT_PRSTATUS" || true)
    if [[ "$n_prstatus" -ge "$n_threads" ]]; then
        pass "mt: $n_prstatus NT_PRSTATUS notes (>= $n_threads threads)"
    else
        fail "mt: at least $n_threads NT_PRSTATUS notes" \
             "got $n_prstatus - some threads may not have been seized"
    fi

    if kill -0 "$pid" 2>/dev/null; then
        pass "mt: multi-threaded target still alive"
    else
        fail "mt: multi-threaded target still alive"
    fi

    stop_target "$pid"
}

# -- Socket JSON ------------------------------------------------------------
section "Socket and FD harvesting"

t_json_valid() {
    if ! command -v python3 >/dev/null 2>&1; then
        skip "json_valid" "python3 not found"; return
    fi

    start_target "$BIN_DIR/target_sockets" || { fail "json_valid: target startup"; return; }
    local pid="$TARGET_PID"

    run_qcore "$pid" || { fail "json_valid: qcore failed"; stop_target "$pid"; return; }

    if python3 -m json.tool "core.$pid.sockets.json" >/dev/null 2>&1; then
        pass "json_valid: sockets JSON is well-formed"
    else
        fail "json_valid: sockets JSON is well-formed" \
             "$(python3 -m json.tool "core.$pid.sockets.json" 2>&1 | head -3)"
    fi

    stop_target "$pid"
}

t_json_tcp() {
    if ! command -v python3 >/dev/null 2>&1; then
        skip "json_tcp" "python3 not found"; return
    fi

    start_target "$BIN_DIR/target_sockets" || { fail "json_tcp: target startup"; return; }
    local pid="$TARGET_PID"
    local tcp_port
    tcp_port=$(field_of "tcp_port" "$TARGET_LINE")

    run_qcore "$pid" || { fail "json_tcp: qcore failed"; stop_target "$pid"; return; }

    local json
    json=$(cat "core.$pid.sockets.json" 2>/dev/null)

    if echo "$json" | grep -qE '"type".*"(tcp4|tcp6)"'; then
        pass "json_tcp: TCP socket type present"
    else
        fail "json_tcp: TCP socket type present"
    fi

    if [[ -n "$tcp_port" ]] && echo "$json" | grep -q ":$tcp_port"; then
        pass "json_tcp: correct port ($tcp_port) in JSON"
    else
        fail "json_tcp: correct port ($tcp_port) in JSON" \
             "port not found in: $(echo "$json" | grep local || echo '(no local key)')"
    fi

    if echo "$json" | grep -q '"LISTEN"'; then
        pass "json_tcp: socket state is LISTEN"
    else
        fail "json_tcp: socket state is LISTEN"
    fi

    stop_target "$pid"
}

t_json_unix() {
    if ! command -v python3 >/dev/null 2>&1; then
        skip "json_unix" "python3 not found"; return
    fi

    start_target "$BIN_DIR/target_sockets" || { fail "json_unix: target startup"; return; }
    local pid="$TARGET_PID"
    local unix_path
    unix_path=$(field_of "unix_path" "$TARGET_LINE")

    run_qcore "$pid" || { fail "json_unix: qcore failed"; stop_target "$pid"; return; }

    local json
    json=$(cat "core.$pid.sockets.json" 2>/dev/null)

    if echo "$json" | grep -q '"type".*"unix"'; then
        pass "json_unix: Unix socket type present"
    else
        fail "json_unix: Unix socket type present"
    fi

    if [[ -n "$unix_path" ]] && echo "$json" | grep -q "$unix_path"; then
        pass "json_unix: correct path ($unix_path) captured"
    else
        fail "json_unix: correct path ($unix_path) captured" \
             "path not found in JSON"
    fi

    stop_target "$pid"
}

t_json_regular_fds() {
    if ! command -v python3 >/dev/null 2>&1; then
        skip "json_fds" "python3 not found"; return
    fi

    start_target "$BIN_DIR/target_simple" || { fail "json_fds: target startup"; return; }
    local pid="$TARGET_PID"

    run_qcore "$pid" || { fail "json_fds: qcore failed"; stop_target "$pid"; return; }

    # Any process should have at least stdin/stdout/stderr (fd 0/1/2)
    local count
    count=$(python3 -c "
import json, sys
d = json.load(open('core.$pid.sockets.json'))
print(len(d['fds']))
" 2>/dev/null || echo 0)

    if [[ "$count" -ge 3 ]]; then
        pass "json_fds: $count FDs captured (>= stdin/stdout/stderr)"
    else
        fail "json_fds: at least 3 FDs (stdin/stdout/stderr)" "got $count"
    fi

    stop_target "$pid"
}

# -- GDB tests (optional) ---------------------------------------------------
section "GDB integration"

HAS_GDB=0
command -v gdb >/dev/null 2>&1 && HAS_GDB=1

t_gdb_loads() {
    [[ $HAS_GDB -eq 1 ]] || { skip "gdb_loads" "gdb not installed"; return; }

    start_target "$BIN_DIR/target_simple" || { fail "gdb_loads: target startup"; return; }
    local pid="$TARGET_PID"

    run_qcore "$pid" || { fail "gdb_loads: qcore failed"; stop_target "$pid"; return; }

    local gdb_out
    gdb_out=$(gdb --batch \
        -ex "set confirm off" \
        -ex "core-file core.$pid" \
        -ex "quit" \
        "$BIN_DIR/target_simple" 2>&1)

    [[ $VERBOSE -eq 1 ]] && echo "$gdb_out" | sed 's/^/    /'

    if echo "$gdb_out" | grep -qi "Truncated\|corrupt\|error reading"; then
        fail "gdb_loads: GDB loads core without errors" \
             "$(echo "$gdb_out" | grep -i "truncat\|corrupt\|error" | head -3)"
    else
        pass "gdb_loads: GDB loads core without truncation errors"
    fi

    # "Core was generated by" line proves GDB recognised it
    if echo "$gdb_out" | grep -q "Core was generated by"; then
        pass "gdb_loads: GDB identifies the generating process"
    else
        fail "gdb_loads: GDB identifies the generating process" \
             "missing 'Core was generated by' line"
    fi

    stop_target "$pid"
}

t_gdb_backtrace() {
    [[ $HAS_GDB -eq 1 ]] || { skip "gdb_backtrace" "gdb not installed"; return; }

    start_target "$BIN_DIR/target_simple" || { fail "gdb_bt: target startup"; return; }
    local pid="$TARGET_PID"

    run_qcore "$pid" || { fail "gdb_bt: qcore failed"; stop_target "$pid"; return; }

    local bt_out
    bt_out=$(gdb --batch \
        -ex "set confirm off" \
        -ex "core-file core.$pid" \
        -ex "thread 1" \
        -ex "bt" \
        -ex "quit" \
        "$BIN_DIR/target_simple" 2>&1)

    [[ $VERBOSE -eq 1 ]] && echo "$bt_out" | sed 's/^/    /'

    # A valid backtrace has at least one frame line "#N  "
    local n_frames
    n_frames=$(echo "$bt_out" | grep -cE '^#[0-9]' || true)
    if [[ "$n_frames" -ge 1 ]]; then
        pass "gdb_backtrace: $n_frames backtrace frames"
    else
        fail "gdb_backtrace: at least 1 backtrace frame" \
             "$(echo "$bt_out" | tail -5)"
    fi

    # PIE binaries may not resolve symbol names without explicit load offsets;
    # accept either named symbols or a healthy frame count.
    if echo "$bt_out" | grep -qE 'in (main|pause|worker|_start|__libc)'; then
        pass "gdb_backtrace: named symbols in backtrace"
    elif [[ "$n_frames" -ge 3 ]]; then
        pass "gdb_backtrace: $n_frames frames (PIE - symbols unresolved but stack intact)"
    else
        fail "gdb_backtrace: at least 3 backtrace frames with symbols" \
             "$(echo "$bt_out" | grep '^#' | head -5)"
    fi

    stop_target "$pid"
}

t_gdb_threads() {
    [[ $HAS_GDB -eq 1 ]] || { skip "gdb_threads" "gdb not installed"; return; }

    start_target "$BIN_DIR/target_mt" || { fail "gdb_threads: target startup"; return; }
    local pid="$TARGET_PID"
    local n_threads
    n_threads=$(field_of "threads" "$TARGET_LINE")
    n_threads="${n_threads:-8}"

    run_qcore "$pid" || { fail "gdb_threads: qcore failed"; stop_target "$pid"; return; }

    local gdb_out
    gdb_out=$(gdb --batch \
        -ex "set confirm off" \
        -ex "core-file core.$pid" \
        -ex "info threads" \
        -ex "quit" \
        "$BIN_DIR/target_mt" 2>&1)

    [[ $VERBOSE -eq 1 ]] && echo "$gdb_out" | sed 's/^/    /'

    # GDB prints either "Thread 0x... (LWP <tid>)" or just "LWP <tid>" depending
    # on the glibc thread library version.  Match both forms.
    local gdb_thread_count
    gdb_thread_count=$(echo "$gdb_out" | grep -cE '^\s*\*?\s*[0-9]+\s+(LWP|Thread)\s' || true)
    if [[ "$gdb_thread_count" -ge "$n_threads" ]]; then
        pass "gdb_threads: GDB sees $gdb_thread_count threads (>= $n_threads)"
    else
        fail "gdb_threads: GDB sees all $n_threads threads" \
             "GDB reported $gdb_thread_count - raw output:" \
             "$(echo "$gdb_out" | grep -E 'Thread|LWP|Id ' | head -10)"
    fi

    stop_target "$pid"
}

# -- Register fidelity ------------------------------------------------------
section "Register fidelity"

t_register_sentinels() {
    [[ $HAS_GDB -eq 1 ]] || { skip "registers" "gdb not installed"; return; }

    start_target "$BIN_DIR/target_registers" || { fail "registers: target startup"; return; }
    local pid="$TARGET_PID"

    # The target prints the expected values; parse them
    local exp_rbx exp_r12 exp_r13
    exp_rbx=$(field_of "rbx" "$TARGET_LINE")
    exp_r12=$(field_of "r12" "$TARGET_LINE")
    exp_r13=$(field_of "r13" "$TARGET_LINE")

    # Brief delay to ensure the target has reached the pause syscall
    sleep 0.1

    run_qcore "$pid" || { fail "registers: qcore failed"; stop_target "$pid"; return; }

    local gdb_out
    gdb_out=$(gdb --batch \
        -ex "set confirm off" \
        -ex "core-file core.$pid" \
        -ex "info registers rbx r12 r13" \
        -ex "quit" \
        "$BIN_DIR/target_registers" 2>&1)

    [[ $VERBOSE -eq 1 ]] && echo "$gdb_out" | sed 's/^/    /'

    for reg_pair in "rbx:$exp_rbx" "r12:$exp_r12" "r13:$exp_r13"; do
        local reg="${reg_pair%%:*}"
        local expected="${reg_pair##*:}"
        # Strip leading 0x, lowercase for comparison
        local expected_bare
        expected_bare=$(echo "$expected" | sed 's/^0x//I' | tr '[:upper:]' '[:lower:]')

        if echo "$gdb_out" | grep -i "$reg" | grep -qi "$expected_bare"; then
            pass "registers: $reg = $expected"
        else
            local actual
            actual=$(echo "$gdb_out" | grep -i "^$reg\b" | head -1)
            fail "registers: $reg = $expected" \
                 "gdb reported: ${actual:-<not found>}"
        fi
    done

    stop_target "$pid"
}

# -- Sockets output file created --------------------------------------------
t_sockets_file_created() {
    start_target "$BIN_DIR/target_simple" || { fail "sockets_file: target startup"; return; }
    local pid="$TARGET_PID"

    run_qcore "$pid" || { fail "sockets_file: qcore failed"; stop_target "$pid"; return; }

    if [[ -f "core.$pid.sockets.json" ]]; then
        pass "sockets_file: core.$pid.sockets.json created"
    else
        fail "sockets_file: core.$pid.sockets.json created"
    fi

    stop_target "$pid"
}

# -- Main -------------------------------------------------------------------
main() {
    echo -e "${BOLD}qcore test suite${NC}"
    echo "qcore:    $QCORE"
    echo "targets:  $BIN_DIR"

    preflight

    # Change to a temp dir so core files don't litter the source tree
    local workdir
    workdir=$(mktemp -d /tmp/qcore_tests_XXXXXX)
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
    t_target_alive
    t_core_size

    section "Memory content"
    t_marker_string

    section "Multi-threaded target"
    t_multithreaded

    section "Socket / FD harvesting"
    t_sockets_file_created
    t_json_valid
    t_json_tcp
    t_json_unix
    t_json_regular_fds

    section "GDB integration"
    t_gdb_loads
    t_gdb_backtrace
    t_gdb_threads

    section "Register fidelity"
    t_register_sentinels

    # -- Summary ------------------------------------------------------------
    echo ""
    echo -e "${BOLD}Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, ${YELLOW}$SKIP skipped${NC}"

    [[ "$FAIL" -eq 0 ]]
}

main "$@"
