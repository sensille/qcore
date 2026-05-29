/*
 * inject.c - Phases 2-4: parasite injection, execution, and teardown.
 *
 * Safe-thread selection
 * ---------------------
 * Prefer a thread that was in pure user-space (orig_rax == -1) when
 * PTRACE_INTERRUPT stopped it.  Prefer non-main threads over the main
 * thread to avoid disrupting the application's event loop.
 * Fall back to any thread if needed.
 *
 * mmap/munmap injection
 * ---------------------
 * Both mmap and munmap are injected via exec_syscall_at, which uses
 * PTRACE_SINGLESTEP from the original PTRACE_EVENT_STOP state.
 *
 * Why PTRACE_SINGLESTEP works cleanly here:
 *   - The thread is at PTRACE_EVENT_STOP from PTRACE_INTERRUPT.
 *   - PT_SYSCALL (TIF_SYSCALL_TRACE) is NOT set -- we never called
 *     PTRACE_SYSCALL -- so there is no two-stop problem.
 *   - When PTRACE_SINGLESTEP resumes from PTRACE_EVENT_STOP, do_signal()
 *     fires (TIF_SIGPENDING from PTRACE_INTERRUPT), clears TIF_SIGPENDING,
 *     and the thread executes exactly one instruction (our mmap syscall).
 *     Exactly one SIGTRAP is generated.
 *
 * Why we do NOT use PTRACE_SYSCALL for injection:
 *   PTRACE_SYSCALL from PTRACE_EVENT_STOP may not produce a syscall-exit
 *   stop for the already-interrupted blocking syscall (the signal-delivery
 *   path bypasses the normal syscall-exit checkpoint).  The thread then
 *   re-enters the blocking call and waitpid hangs.
 *
 * Parasite execution
 * ------------------
 * After mmap, PTRACE_CONT runs the parasite natively.  PTRACE_CONT clears
 * TIF_SYSCALL_TRACE (not that it was set, but belt-and-suspenders).  The
 * parasite's own clone() calls are not intercepted.  The munmap injection
 * after the int3 trap also uses PTRACE_SINGLESTEP -- safe because no
 * PT_SYSCALL is active and PTRACE_CONT further ensured a clean state.
 *
 * Restoration
 * -----------
 * Injector thread: restore safe_saved_regs.
 *   - orig_rax == -1 (user-space): plain restore, nothing to fix.
 *   - otherwise: if rax contains a kernel restart code or equals orig_rax
 *     (syscall-entry state where rax == syscall number), replace rax with
 *     -EINTR.  The application sees a normal EINTR error return.
 *
 *   We deliberately do NOT use rip-2.  rip-2 re-executes the syscall from
 *   scratch, which is unsafe for stateful syscalls: io_uring_enter may have
 *   already consumed submission queue entries, nanosleep loses its remaining
 *   timeout, partial write() sends data twice, etc.  -EINTR is always safe.
 *
 * Non-injector threads: plain PTRACE_DETACH.  TIF_SIGPENDING is still set
 * (from PTRACE_INTERRUPT), so arch_do_signal_or_restart() fires on detach
 * and handles each syscall's restart semantics correctly:
 *   ERESTARTSYS / ERESTARTNOINTR  -> transparent kernel restart
 *   ERESTARTNOHAND / RESTARTBLOCK -> -EINTR to user-space
 * We do NOT call PTRACE_SETREGS on non-injector threads.
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
 * Execute a single syscall in tid's context at rip via PTRACE_SINGLESTEP.
 * Safe when PT_SYSCALL is not set (i.e. thread is at PTRACE_EVENT_STOP or
 * at a SIGTRAP stop after PTRACE_CONT cleared TIF_SYSCALL_TRACE).
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

static int find_safe_thread(qcore_state_t *state)
{
    pid_t main_tid = state->target_pid;

    /* 1. Non-main thread in user-space (orig_rax == -1). */
    for (int i = 0; i < state->threads.count; i++) {
        const thread_info_t *t = &state->threads.data[i];
        if (!t->regs_valid || t->tid == main_tid) continue;
        if (t->regs.orig_rax == (unsigned long long)-1) return i;
    }
    /* 2. Main thread in user-space. */
    for (int i = 0; i < state->threads.count; i++) {
        const thread_info_t *t = &state->threads.data[i];
        if (!t->regs_valid || t->tid != main_tid) continue;
        if (t->regs.orig_rax == (unsigned long long)-1) return i;
    }
    /* 3. Any non-main thread (will get -EINTR on restore). */
    for (int i = 0; i < state->threads.count; i++) {
        const thread_info_t *t = &state->threads.data[i];
        if (t->regs_valid && t->tid != main_tid) return i;
    }
    /* 4. Main thread as last resort. */
    for (int i = 0; i < state->threads.count; i++) {
        if (state->threads.data[i].regs_valid) return i;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Cleanup                                                             */

/*
 * Restore the safe thread to its original state and free the parasite
 * mapping.  Called on the success path AND every post-injection failure
 * path, so the target is never left with a corrupted RIP (which would
 * resume into the parasite's ud2 and crash the target) or a leaked RWX
 * mapping.  Best-effort: ptrace errors here are ignored because we are
 * already on a teardown path and the caller will detach regardless.
 */
static void restore_safe_thread(qcore_state_t *state, pid_t safe_tid,
                                uint64_t rip)
{
    /* Free the parasite pages if still mapped. */
    if (state->mmap_addr) {
        struct user_regs_struct unmap_regs = state->safe_saved_regs;
        unmap_regs.rax = 11;          /* SYS_munmap */
        unmap_regs.rdi = state->mmap_addr;
        unmap_regs.rsi = PARASITE_MMAP_SIZE;
        state->safe_bytes_modified = 1;
        exec_syscall_at(safe_tid, rip, &unmap_regs);
        state->safe_bytes_modified = 0;
        state->mmap_addr = 0;
    }

    /* Restore original registers.  Convert an interrupted syscall's restart
     * code (or syscall-entry state where rax == orig_rax) to -EINTR; never
     * rip-2 (re-executing stateful syscalls is unsafe). */
    struct user_regs_struct restore_regs = state->safe_saved_regs;
    if (restore_regs.orig_rax != (unsigned long long)-1) {
        if (is_restart_code((long long)restore_regs.rax) ||
            restore_regs.rax == restore_regs.orig_rax)
            restore_regs.rax = (unsigned long long)(-EINTR);
    }
    ptrace(PTRACE_SETREGS, safe_tid, NULL, &restore_regs);
    state->safe_bytes_modified = 0;
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
    printf("[phase2] safe thread TID=%d  RIP=0x%llx  %s\n",
           (int)safe_tid, (unsigned long long)rip,
           userspace ? "(was in user-space)"
                     : "(was in syscall - will return -EINTR)");

    double t_mmap_start = qcore_now_ms();

    /* ---- 2. Allocate parasite pages via injected mmap ------------ */
    struct user_regs_struct mmap_regs = state->safe_saved_regs;
    mmap_regs.rax = 9;
    mmap_regs.rdi = 0;
    mmap_regs.rsi = PARASITE_MMAP_SIZE;
    mmap_regs.rdx = 7;
    mmap_regs.r10 = 0x22;
    mmap_regs.r8  = (unsigned long long)-1;
    mmap_regs.r9  = 0;

    state->safe_bytes_modified = 1;
    long mmap_ret = exec_syscall_at(safe_tid, rip, &mmap_regs);
    state->safe_bytes_modified = 0;
    if (mmap_ret == LONG_MIN || mmap_ret < 0) {
        fprintf(stderr, "[inject] mmap failed: %ld\n", mmap_ret);
        goto fail;
    }
    state->mmap_addr = (uint64_t)mmap_ret;
    printf("[timing]  mmap injection:    %.2f ms\n",
           qcore_now_ms() - t_mmap_start);

    /* ---- 3. Write parasite shellcode ----------------------------- */
    uint64_t code_addr = state->mmap_addr + CODE_OFF;
    if ((int)parasite_bin_len > 4096) {
        fprintf(stderr, "[inject] parasite too large\n"); goto fail;
    }
    if (poke_bytes(safe_tid, code_addr, parasite_bin, parasite_bin_len) < 0)
        goto fail;

    /* ---- 4. Run parasite ----------------------------------------- */
    /* Read the target's RLIMIT_NOFILE soft limit so the parasite closes
     * all fds the process may hold, not just the hardcoded first 1024.
     * Pass it in r14.  Cap at 1M to bound the loop on RLIM_INFINITY. */
    long fd_limit = 65536;
    {
        struct rlimit rl;
        if (prlimit((pid_t)state->target_pid, RLIMIT_NOFILE, NULL, &rl) == 0 &&
            rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur > 0)
            fd_limit = (long)rl.rlim_cur;
        if (fd_limit > 1048576)
            fd_limit = 1048576;
    }

    struct user_regs_struct run_regs = state->safe_saved_regs;
    run_regs.rip = code_addr;
    run_regs.r15 = state->mmap_addr;  /* scratch/stack/code base  */
    run_regs.r14 = (unsigned long long)fd_limit;  /* fd close limit */
    run_regs.rax = 0;

    printf("[phase3] fd close limit: %ld\n", fd_limit);

    if (ptrace(PTRACE_SETREGS, safe_tid, NULL, &run_regs) == -1) {
        perror("SETREGS (run parasite)"); goto fail;
    }

    double t_parasite_start = qcore_now_ms();

    /* PTRACE_CONT: clears TIF_SYSCALL_TRACE so the parasite's clone()
     * calls are not intercepted and munmap SINGLESTEP below is clean. */
    if (ptrace(PTRACE_CONT, safe_tid, 0, 0) == -1) {
        perror("PTRACE_CONT (run parasite)"); goto fail;
    }

    /* ---- 5. Wait for int3 from parasite -------------------------- */
    int status;
    for (;;) {
        pid_t who = waitpid(safe_tid, &status, __WALL);
        if (who == -1) { perror("waitpid (parasite)"); goto fail; }
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) break;
        if (WIFSTOPPED(status)) {
            if (ptrace(PTRACE_CONT, safe_tid, 0,
                       (void *)(long)WSTOPSIG(status)) == -1) {
                perror("PTRACE_CONT (signal)"); goto fail;
            }
            continue;
        }
        fprintf(stderr, "[inject] unexpected status 0x%x\n", status);
        goto fail;
    }

    printf("[timing]  parasite (double-fork): %.2f ms\n",
           qcore_now_ms() - t_parasite_start);

    /* ---- 6. Extract child2_pid from %rax ------------------------- */
    struct user_regs_struct trap_regs;
    if (ptrace(PTRACE_GETREGS, safe_tid, NULL, &trap_regs) == -1) {
        perror("GETREGS (trap)"); goto fail;
    }
    long long raw = (long long)trap_regs.rax;
    if (raw <= 0) {
        if (raw == -1)
            fprintf(stderr, "[inject] parasite spin timed out "
                    "(Child 1 never wrote child2_pid; "
                    "likely OOM-killed or clone() failed)\n");
        else
            fprintf(stderr, "[inject] parasite clone() failed: errno=%lld\n",
                    -raw);
        goto fail;
    }
    state->child2_pid = (pid_t)raw;
    printf("[phase3] parasite complete - child2 PID=%d\n", (int)state->child2_pid);

    /* ---- 7. Free parasite mapping + restore safe thread ---------- */
    double t_restore = qcore_now_ms();
    restore_safe_thread(state, safe_tid, rip);
    printf("[timing]  munmap + restore:   %.2f ms\n",
           qcore_now_ms() - t_restore);

    /* ---- 8. Detach all threads ----------------------------------- */
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

fail:
    /* Post-injection failure: restore the safe thread and free the mapping
     * so the target survives.  The caller (main.c) detaches all threads. */
    restore_safe_thread(state, safe_tid, rip);
    return -1;
}
