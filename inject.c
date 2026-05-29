/*
 * inject.c - Phases 2-4: parasite injection, execution, and teardown.
 *
 * Safe-thread selection
 * ---------------------
 * Prefer a thread that was in pure user-space (orig_rax == -1): restoration
 * is a plain register write with no syscall-restart concerns.
 *
 * If all threads are in blocking syscalls, call PTRACE_SYSCALL once to get
 * the first ptrace-syscall stop (entry OR exit).  Both are usable:
 *
 *  Exit stop  (rax != orig_rax): thread just returned -EINTR in user-space.
 *  Entry stop (rax == orig_rax): thread executed the syscall instruction but
 *             the kernel hasn't run the syscall yet; we can change rax to
 *             redirect it to mmap without ever entering the blocking call.
 *
 * We stop after ONE PTRACE_SYSCALL call to avoid letting the thread re-enter
 * a blocking syscall (which would cause waitpid to hang).
 *
 * mmap injection
 * --------------
 * User-space thread: exec_syscall_at uses PTRACE_SINGLESTEP.  Safe because
 * PT_SYSCALL (TIF_SYSCALL_TRACE) is not set.
 *
 * PTRACE_SYSCALL thread: inject_mmap_via_syscall drives entry+exit stops
 * using PTRACE_SYSCALL throughout.  We never use PTRACE_SINGLESTEP while
 * PT_SYSCALL is set to avoid the two-stop problem (syscall-entry stop +
 * singlestep stop arriving in sequence).
 *
 * Parasite execution
 * ------------------
 * PTRACE_CONT is called to run the parasite.  PTRACE_CONT clears
 * TIF_SYSCALL_TRACE (PT_SYSCALL), so the parasite's own clone() calls are
 * not intercepted and the munmap injection (exec_syscall_at / SINGLESTEP)
 * after the int3 trap generates exactly one stop.
 *
 * Restoration
 * -----------
 * Injector thread:
 *  - User-space (orig_rax==-1): restore as-is.
 *  - Syscall exit (rax != orig_rax, no restart code): restore as-is; rax
 *    is a valid userspace return value (-EINTR, success count, etc.).
 *  - Syscall entry (rax == orig_rax) or restart code: set rax = -EINTR.
 *    We do NOT use rip-2 because rip-2 re-executes the syscall from
 *    scratch, which is unsafe for stateful syscalls (io_uring_enter with
 *    consumed SQEs, nanosleep losing its remaining timeout, etc.).
 *
 * Non-injector threads: plain PTRACE_DETACH.  TIF_SIGPENDING is still set
 * (from PTRACE_INTERRUPT), so arch_do_signal_or_restart() fires on detach
 * and applies the kernel's per-syscall restart policy -- the correct
 * authority for each syscall type.
 */

#include "qcore.h"
#include "parasite.h"

#define PARASITE_PAGES      3
#define PARASITE_MMAP_SIZE  (PARASITE_PAGES * 4096)
#define SCRATCH_OFF         0
#define CHILD1_STACK_OFF    4096
#define CHILD1_STACK_TOP    8176
#define CODE_OFF            8192

/* ------------------------------------------------------------------ */
/* Helpers                                                             */

static int is_restart_code(long long rax)
{
    switch (rax) {
    case -512: case -513: case -514: case -516:
        return 1;
    default:
        return 0;
    }
}

/*
 * Execute a single syscall via PTRACE_SINGLESTEP.
 * Safe only when TIF_SYSCALL_TRACE (PT_SYSCALL) is NOT set -- i.e. the
 * thread came from a user-space stop or from PTRACE_CONT which cleared it.
 */
static long exec_syscall_at(pid_t tid, uint64_t rip,
                             struct user_regs_struct *mod_regs)
{
    errno = 0;
    unsigned long orig = ptrace(PTRACE_PEEKTEXT, tid, (void *)rip, NULL);
    if (errno) { perror("PEEKTEXT"); return LONG_MIN; }

    unsigned long patched = (orig & ~0xFFFFUL) | 0x050FUL;
    if (ptrace(PTRACE_POKETEXT, tid, (void *)rip, (void *)patched) == -1) {
        perror("POKETEXT"); return LONG_MIN;
    }

    mod_regs->rip = rip;
    if (ptrace(PTRACE_SETREGS, tid, NULL, mod_regs) == -1) {
        perror("SETREGS"); return LONG_MIN;
    }
    if (ptrace(PTRACE_SINGLESTEP, tid, 0, 0) == -1) {
        perror("SINGLESTEP"); return LONG_MIN;
    }
    int status;
    if (waitpid(tid, &status, __WALL) == -1) {
        perror("waitpid SINGLESTEP"); return LONG_MIN;
    }

    struct user_regs_struct res;
    if (ptrace(PTRACE_GETREGS, tid, NULL, &res) == -1) {
        perror("GETREGS result"); return LONG_MIN;
    }
    long result = (long)res.rax;

    if (ptrace(PTRACE_POKETEXT, tid, (void *)rip, (void *)orig) == -1) {
        perror("POKETEXT restore"); return LONG_MIN;
    }
    return result;
}

/*
 * Inject a mmap syscall via PTRACE_SYSCALL when the thread is at a
 * PTRACE_SYSCALL stop (entry or exit).  Using PTRACE_SINGLESTEP here
 * would generate two stops (syscall-entry + singlestep) because
 * TIF_SYSCALL_TRACE is still set.
 *
 * Entry stop (cur->rax == cur->orig_rax):
 *   The kernel is about to run the original blocking syscall.  We replace
 *   rax with SYS_mmap; one PTRACE_SYSCALL call lets mmap run and stops at
 *   the mmap exit.
 *
 * Exit stop (cur->rax != cur->orig_rax):
 *   The original syscall already returned (e.g. -EINTR).  We write a
 *   syscall opcode at rip so the thread will execute it next, set rax to
 *   SYS_mmap, then drive through entry+exit with two PTRACE_SYSCALL calls.
 */
static long inject_mmap_via_syscall(pid_t tid, uint64_t rip,
                                     const struct user_regs_struct *cur,
                                     const struct user_regs_struct *mmap_args)
{
    int at_entry = (cur->orig_rax != (unsigned long long)-1 &&
                    cur->rax == cur->orig_rax);
    unsigned long orig_bytes = 0;

    if (!at_entry) {
        errno = 0;
        orig_bytes = ptrace(PTRACE_PEEKTEXT, tid, (void *)rip, NULL);
        if (errno) { perror("PEEKTEXT mmap"); return LONG_MIN; }
        unsigned long patched = (orig_bytes & ~0xFFFFUL) | 0x050FUL;
        if (ptrace(PTRACE_POKETEXT, tid, (void *)rip, (void *)patched) == -1) {
            perror("POKETEXT mmap"); return LONG_MIN;
        }
    }

    struct user_regs_struct regs = *mmap_args;
    regs.rip = rip;
    if (ptrace(PTRACE_SETREGS, tid, NULL, &regs) == -1) {
        perror("SETREGS mmap"); return LONG_MIN;
    }

    if (!at_entry) {
        /* Consume the mmap syscall-entry stop. */
        if (ptrace(PTRACE_SYSCALL, tid, 0, 0) == -1) {
            perror("PTRACE_SYSCALL entry"); return LONG_MIN;
        }
        int st;
        if (waitpid(tid, &st, __WALL) == -1) { perror("waitpid entry"); return LONG_MIN; }
    }

    /* Let the mmap syscall complete; catch exit stop. */
    if (ptrace(PTRACE_SYSCALL, tid, 0, 0) == -1) {
        perror("PTRACE_SYSCALL exit"); return LONG_MIN;
    }
    int st;
    if (waitpid(tid, &st, __WALL) == -1) { perror("waitpid exit"); return LONG_MIN; }

    struct user_regs_struct res;
    if (ptrace(PTRACE_GETREGS, tid, NULL, &res) == -1) {
        perror("GETREGS mmap"); return LONG_MIN;
    }
    long result = (long)res.rax;

    if (!at_entry)
        ptrace(PTRACE_POKETEXT, tid, (void *)rip, (void *)orig_bytes);

    return result;
}

static int poke_bytes(pid_t tid, uint64_t addr,
                      const unsigned char *data, size_t len)
{
    size_t i = 0;
    for (; i + 8 <= len; i += 8) {
        unsigned long word;
        memcpy(&word, data + i, 8);
        if (ptrace(PTRACE_POKETEXT, tid, (void *)(addr + i),
                   (void *)word) == -1) {
            perror("POKETEXT parasite"); return -1;
        }
    }
    if (i < len) {
        errno = 0;
        unsigned long word = ptrace(PTRACE_PEEKTEXT, tid,
                                    (void *)(addr + i), NULL);
        if (errno) { perror("PEEKTEXT last word"); return -1; }
        memcpy(&word, data + i, len - i);
        if (ptrace(PTRACE_POKETEXT, tid, (void *)(addr + i),
                   (void *)word) == -1) {
            perror("POKETEXT last word"); return -1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Safe thread selection                                               */

/*
 * Call PTRACE_SYSCALL once to get the first ptrace-syscall stop (entry
 * or exit).  We stop after ONE call to avoid letting the thread re-enter
 * a blocking syscall (which would make waitpid hang forever).
 *
 * Both entry and exit stops are usable injection points:
 *  - Entry: redirect to mmap by changing rax before the syscall runs.
 *  - Exit:  write mmap opcode at rip so it executes on next resume.
 */
static int step_to_first_syscall_stop(qcore_state_t *state)
{
    int idx = -1;
    for (int i = 0; i < state->threads.count; i++) {
        if (!state->threads.data[i].regs_valid) continue;
        if (state->threads.data[i].tid == state->target_pid) continue;
        idx = i;
        break;
    }
    if (idx < 0) {
        for (int i = 0; i < state->threads.count; i++) {
            if (state->threads.data[i].regs_valid) { idx = i; break; }
        }
    }
    if (idx < 0) return -1;

    pid_t tid = state->threads.data[idx].tid;

    if (ptrace(PTRACE_SYSCALL, tid, 0, 0) == -1) {
        perror("PTRACE_SYSCALL"); return -1;
    }
    int status;
    if (waitpid(tid, &status, __WALL) == -1) {
        perror("waitpid syscall-stop"); return -1;
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "TID %d exited during syscall step\n", (int)tid);
        return -1;
    }

    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, tid, NULL, &r) == -1) {
        perror("PTRACE_GETREGS syscall-stop"); return -1;
    }

    state->threads.data[idx].regs = r;
    state->threads.data[idx].regs_valid = 1;

    int at_entry = (r.orig_rax != (unsigned long long)-1 &&
                    r.rax == r.orig_rax);
    printf("[phase2] TID=%d at syscall-%s (syscall=%llu retval=%lld)\n",
           (int)tid,
           at_entry ? "entry" : "exit",
           (unsigned long long)r.orig_rax,
           (long long)r.rax);
    return idx;
}

static int find_safe_thread(qcore_state_t *state)
{
    pid_t main_tid = state->target_pid;

    for (int i = 0; i < state->threads.count; i++) {
        const thread_info_t *t = &state->threads.data[i];
        if (!t->regs_valid || t->tid == main_tid) continue;
        if (t->regs.orig_rax == (unsigned long long)-1) return i;
    }
    for (int i = 0; i < state->threads.count; i++) {
        const thread_info_t *t = &state->threads.data[i];
        if (!t->regs_valid || t->tid != main_tid) continue;
        if (t->regs.orig_rax == (unsigned long long)-1) return i;
    }
    return step_to_first_syscall_stop(state);
}

/* ------------------------------------------------------------------ */
/* Main entry point                                                    */

int inject_parasite(qcore_state_t *state)
{
    /* ---- 1. Select safe thread ------------------------------------ */
    int sidx = find_safe_thread(state);
    if (sidx < 0) {
        fprintf(stderr, "[inject] no usable injection thread\n");
        return -1;
    }
    state->safe_thread_idx = sidx;

    pid_t safe_tid = state->threads.data[sidx].tid;
    uint64_t rip   = state->threads.data[sidx].regs.rip;
    state->safe_saved_regs = state->threads.data[sidx].regs;

    int userspace = (state->safe_saved_regs.orig_rax == (unsigned long long)-1);
    int at_entry  = (!userspace &&
                     state->safe_saved_regs.rax == state->safe_saved_regs.orig_rax);
    const char *desc = userspace  ? "(user-space, SINGLESTEP injection)" :
                       at_entry   ? "(syscall-entry, PTRACE_SYSCALL injection)" :
                                    "(syscall-exit,  PTRACE_SYSCALL injection)";
    printf("[phase2] safe thread TID=%d  RIP=0x%llx  %s\n",
           (int)safe_tid, (unsigned long long)rip, desc);

    double t_mmap_start = qcore_now_ms();

    /* ---- 2. Allocate parasite pages ------------------------------ */
    struct user_regs_struct mmap_regs = state->safe_saved_regs;
    mmap_regs.rax = 9;
    mmap_regs.rdi = 0;
    mmap_regs.rsi = PARASITE_MMAP_SIZE;
    mmap_regs.rdx = 7;
    mmap_regs.r10 = 0x22;
    mmap_regs.r8  = (unsigned long long)-1;
    mmap_regs.r9  = 0;

    long mmap_ret;
    if (userspace) {
        state->safe_bytes_modified = 1;
        mmap_ret = exec_syscall_at(safe_tid, rip, &mmap_regs);
        state->safe_bytes_modified = 0;
    } else {
        mmap_ret = inject_mmap_via_syscall(safe_tid, rip,
                                            &state->safe_saved_regs,
                                            &mmap_regs);
    }

    if (mmap_ret == LONG_MIN || mmap_ret < 0) {
        fprintf(stderr, "[inject] mmap failed: %ld\n", mmap_ret);
        return -1;
    }
    state->mmap_addr = (uint64_t)mmap_ret;
    printf("[timing]  mmap injection:    %.2f ms\n",
           qcore_now_ms() - t_mmap_start);

    /* ---- 3. Write parasite shellcode ----------------------------- */
    uint64_t code_addr = state->mmap_addr + CODE_OFF;
    if ((int)parasite_bin_len > 4096) {
        fprintf(stderr, "[inject] parasite too large\n"); return -1;
    }
    if (poke_bytes(safe_tid, code_addr, parasite_bin, parasite_bin_len) < 0)
        return -1;

    /* ---- 4. Run parasite ----------------------------------------- */
    struct user_regs_struct run_regs = state->safe_saved_regs;
    run_regs.rip = code_addr;
    run_regs.r15 = state->mmap_addr;
    run_regs.rax = 0;

    if (ptrace(PTRACE_SETREGS, safe_tid, NULL, &run_regs) == -1) {
        perror("SETREGS (run parasite)"); return -1;
    }

    double t_parasite_start = qcore_now_ms();

    /*
     * PTRACE_CONT clears TIF_SYSCALL_TRACE (PT_SYSCALL).  After this,
     * the parasite's clone() calls are not intercepted by ptrace, and
     * exec_syscall_at (SINGLESTEP) for munmap is safe (one stop only).
     */
    if (ptrace(PTRACE_CONT, safe_tid, 0, 0) == -1) {
        perror("PTRACE_CONT (run parasite)"); return -1;
    }

    /* ---- 5. Wait for int3 from parasite -------------------------- */
    int status;
    for (;;) {
        pid_t who = waitpid(safe_tid, &status, __WALL);
        if (who == -1) { perror("waitpid (parasite)"); return -1; }
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) break;
        if (WIFSTOPPED(status)) {
            if (ptrace(PTRACE_CONT, safe_tid, 0,
                       (void *)(long)WSTOPSIG(status)) == -1) {
                perror("PTRACE_CONT (signal)"); return -1;
            }
            continue;
        }
        fprintf(stderr, "[inject] unexpected status 0x%x\n", status);
        return -1;
    }

    printf("[timing]  parasite (double-fork): %.2f ms\n",
           qcore_now_ms() - t_parasite_start);

    /* ---- 6. Extract child2_pid ------------------------------------ */
    struct user_regs_struct trap_regs;
    if (ptrace(PTRACE_GETREGS, safe_tid, NULL, &trap_regs) == -1) {
        perror("GETREGS (trap)"); return -1;
    }
    pid_t child2 = (pid_t)trap_regs.rax;
    if (child2 <= 0) {
        fprintf(stderr, "[inject] bad child2_pid=%d\n", (int)child2);
        return -1;
    }
    state->child2_pid = child2;
    printf("[phase3] parasite complete - child2 PID=%d\n", (int)child2);

    /* ---- 7. Inject munmap ---------------------------------------- */
    /*
     * PTRACE_CONT cleared TIF_SYSCALL_TRACE, so exec_syscall_at
     * (PTRACE_SINGLESTEP) now generates exactly one stop.  Safe.
     */
    double t_munmap_start = qcore_now_ms();

    struct user_regs_struct unmap_regs = state->safe_saved_regs;
    unmap_regs.rax = 11;
    unmap_regs.rdi = state->mmap_addr;
    unmap_regs.rsi = PARASITE_MMAP_SIZE;

    state->safe_bytes_modified = 1;
    long unmap_ret = exec_syscall_at(safe_tid, rip, &unmap_regs);
    state->safe_bytes_modified = 0;
    if (unmap_ret == LONG_MIN || unmap_ret < 0)
        fprintf(stderr, "[inject] munmap warning: %ld\n", unmap_ret);

    state->mmap_addr = 0;

    /* ---- 8. Restore safe thread ---------------------------------- */
    /*
     * Restore to the state captured at the injection point:
     *  - User-space: plain restore, nothing to fix.
     *  - Syscall-exit with valid return (-EINTR, success): restore as-is.
     *  - Syscall-entry (rax == orig_rax) or restart code: set rax=-EINTR.
     *    We never use rip-2: re-executing the syscall from scratch is
     *    unsafe for stateful syscalls (io_uring_enter, partial write, etc.)
     */
    struct user_regs_struct restore_regs = state->safe_saved_regs;
    if (restore_regs.orig_rax != (unsigned long long)-1) {
        if (is_restart_code((long long)restore_regs.rax) ||
            restore_regs.rax == restore_regs.orig_rax)
            restore_regs.rax = (unsigned long long)(-EINTR);
    }
    if (ptrace(PTRACE_SETREGS, safe_tid, NULL, &restore_regs) == -1) {
        perror("SETREGS (restore)"); return -1;
    }
    state->safe_bytes_modified = 0;

    printf("[timing]  munmap + restore:   %.2f ms\n",
           qcore_now_ms() - t_munmap_start);

    /* ---- 9. Detach all threads ----------------------------------- */
    /*
     * Non-injector threads: plain PTRACE_DETACH.  TIF_SIGPENDING is still
     * set (from PTRACE_INTERRUPT), so arch_do_signal_or_restart() fires on
     * detach and handles each syscall's restart policy correctly.
     * We do NOT apply rip-2 or explicit PTRACE_SETREGS here.
     */
    int detached = 0;
    for (int i = 0; i < state->threads.count; i++) {
        pid_t tid = state->threads.data[i].tid;
        if (tid <= 0) continue;
        if (ptrace(PTRACE_DETACH, tid, NULL, NULL) == -1) {
            if (errno == ESRCH) continue;
            fprintf(stderr, "PTRACE_DETACH(%d): %s\n",
                    (int)tid, strerror(errno));
        } else {
            detached++;
        }
    }

    printf("[phase4] parent running again - detached %d thread(s)\n", detached);
    return 0;
}
