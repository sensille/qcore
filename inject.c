/*
 * inject.c - Phases 2-4: parasite injection, execution, and teardown.
 *
 * Choosing the injector thread (safe vs force mode)
 * -------------------------------------------------
 * We hijack one thread to run mmap, the parasite, and munmap.  The safest
 * possible injector is one stopped at a "clean" point:
 *
 *   - pure user-space (orig_rax == -1): restoring its registers is a
 *     perfect no-op; the thread never notices.
 *   - a syscall-EXIT boundary: the syscall already completed with a real
 *     return value, so restoring the registers returns that value normally.
 *
 * In neither case is a kernel restart code in play, so there is zero
 * ambiguity and zero -EINTR risk for the injector.
 *
 * Safe mode (default): if no thread is already in user-space, we "race to
 * the exit" -- resume all threads under PTRACE_SYSCALL so the application
 * runs normally, and wait for ANY thread to reach a syscall-exit (an epoll
 * loop returns, a read completes, ...).  The instant one does, we freeze
 * everyone again and use that thread as a guaranteed-clean injector.
 * If nothing reaches an exit within the timeout (a fully idle process with
 * every thread parked forever), we give up and tell the user to use -f.
 *
 * Force mode (-f): skip the race and hijack any thread, even one stopped
 * mid-syscall.  On restore we put back its exact original registers,
 * including any ERESTART* code in rax; detaching with signal 0 lets the
 * kernel transparently restart the interrupted syscall (verified for
 * ERESTARTSYS/NOINTR/RESTARTBLOCK).  epoll_wait threads still surface a
 * benign -EINTR, exactly as any signal would.
 *
 * mmap/munmap injection uses exec_syscall_at (PTRACE_SINGLESTEP from a
 * non-syscall stop -- one stop, no ambiguity).  The parasite runs via
 * PTRACE_CONT.
 *
 * Restore: we always write back the exact saved registers and detach with
 * 0.  For a clean injector there is no restart code; for a force-mode
 * mid-syscall injector the kernel restarts via the signr==0 path.  We never
 * use rip-2 (re-executing a stateful syscall from scratch is unsafe).
 */

#include "qcore.h"
#include <sys/uio.h>
#include <linux/ptrace.h>   /* struct ptrace_syscall_info, PTRACE_GET_SYSCALL_INFO */
#include "parasite.h"

#define PARASITE_PAGES      3
#define PARASITE_MMAP_SIZE  (PARASITE_PAGES * 4096)
#define SCRATCH_OFF         0
#define CHILD1_STACK_OFF    4096
#define CHILD1_STACK_TOP    8176
#define CODE_OFF            8192

/* ------------------------------------------------------------------ */
/* Helpers                                                             */

/* How long safe mode waits for a thread to reach a syscall-exit before
 * giving up and advising -f.  A process with every thread parked forever
 * in a blocking syscall never yields a clean point. */
#define QCORE_RACE_TIMEOUT_SEC 10

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
/* Injector selection                                                  */

/* Index of the entry for tid, or -1. */
static int thread_index(const qcore_state_t *state, pid_t tid)
{
    for (int i = 0; i < state->threads.count; i++)
        if (state->threads.data[i].tid == tid) return i;
    return -1;
}

/*
 * A thread is "user-space clean" if it was executing user code (not in a
 * syscall) when stopped.  Such a thread is the ideal injector.
 * Prefer non-main threads to avoid disturbing the main event loop.
 */
static int find_userspace_injector(const qcore_state_t *state)
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
    return -1;
}

/* Force-mode fallback: any valid thread, non-main preferred. */
static int find_any_injector(const qcore_state_t *state)
{
    pid_t main_tid = state->target_pid;
    for (int i = 0; i < state->threads.count; i++)
        if (state->threads.data[i].regs_valid &&
            state->threads.data[i].tid != main_tid) return i;
    for (int i = 0; i < state->threads.count; i++)
        if (state->threads.data[i].regs_valid) return i;
    return -1;
}

/* ------------------------------------------------------------------ */
/* Race to the syscall-exit                                            */

/* Is this stop a syscall-exit (vs entry)?  Prefer the authoritative
 * PTRACE_GET_SYSCALL_INFO; fall back to the x86-64 convention that rax ==
 * -ENOSYS at syscall-entry. */
static int at_syscall_exit(pid_t tid, const struct user_regs_struct *r)
{
#ifdef PTRACE_GET_SYSCALL_INFO
    struct ptrace_syscall_info si;
    long n = ptrace(PTRACE_GET_SYSCALL_INFO, tid,
                    (void *)sizeof(si), &si);
    if (n > 0) return si.op == PTRACE_SYSCALL_INFO_EXIT;
#endif
    return (long long)r->rax != -38 /* -ENOSYS */;
}

/* Re-freeze every thread except the winner with PTRACE_INTERRUPT, wait for
 * each to stop, and refresh all saved registers so PT_NOTE reflects the
 * frozen instant. */
static void refreeze_others(qcore_state_t *state, pid_t winner_tid)
{
    for (int i = 0; i < state->threads.count; i++) {
        pid_t tid = state->threads.data[i].tid;
        if (tid <= 0 || tid == winner_tid) continue;
        ptrace(PTRACE_INTERRUPT, tid, 0, 0);
    }
    for (int i = 0; i < state->threads.count; i++) {
        pid_t tid = state->threads.data[i].tid;
        if (tid <= 0 || tid == winner_tid) continue;
        int st;
        if (waitpid(tid, &st, __WALL) == -1) { state->threads.data[i].tid = -1; continue; }
        if (!WIFSTOPPED(st)) { state->threads.data[i].tid = -1; continue; }
        ptrace(PTRACE_GETREGS, tid, NULL, &state->threads.data[i].regs);
    }
}

/* SIGALRM handler for the race timeout: just interrupts the blocking
 * waitpid via EINTR. */
static volatile sig_atomic_t g_race_timed_out;
static void race_alarm(int sig) { (void)sig; g_race_timed_out = 1; }

/*
 * Resume all threads under PTRACE_SYSCALL and wait for any one to reach a
 * syscall-exit, giving a guaranteed-clean injector.  Re-freeze the rest.
 * Returns the injector's thread index, or -1 on timeout/error (in which
 * case all threads are left stopped for the caller to detach).
 */
static int race_for_injector(qcore_state_t *state, int timeout_sec)
{
    /* Enable clean syscall-stop reporting and child tracking. */
    for (int i = 0; i < state->threads.count; i++) {
        pid_t tid = state->threads.data[i].tid;
        if (tid <= 0) continue;
        ptrace(PTRACE_SETOPTIONS, tid, 0,
               (void *)(long)(PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE));
    }

    /* Resume every thread under syscall-tracing; the app now runs. */
    int running = 0;
    for (int i = 0; i < state->threads.count; i++) {
        pid_t tid = state->threads.data[i].tid;
        if (tid <= 0) continue;
        if (ptrace(PTRACE_SYSCALL, tid, 0, 0) == 0) running++;
    }
    if (running == 0) return -1;

    printf("[phase2] no user-space thread; racing %d thread(s) "
           "to a syscall-exit (timeout %ds)\n", running, timeout_sec);

    /* Arm the timeout. */
    g_race_timed_out = 0;
    struct sigaction old_alarm, sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = race_alarm;       /* no SA_RESTART: must interrupt waitpid */
    sigaction(SIGALRM, &sa, &old_alarm);
    alarm((unsigned)timeout_sec);

    int winner_idx = -1;
    while (winner_idx < 0 && !g_race_timed_out) {
        int status;
        pid_t tid = waitpid(-1, &status, __WALL);
        if (tid == -1) {
            if (errno == EINTR) break;     /* timeout */
            perror("waitpid (race)");
            break;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            int idx = thread_index(state, tid);
            if (idx >= 0) state->threads.data[idx].tid = -1;
            continue;
        }
        if (!WIFSTOPPED(status)) continue;

        int sig = WSTOPSIG(status);

        /* Syscall-trace stop is reported as SIGTRAP|0x80 (TRACESYSGOOD). */
        if (sig == (SIGTRAP | 0x80)) {
            struct user_regs_struct r;
            if (ptrace(PTRACE_GETREGS, tid, NULL, &r) == 0 &&
                at_syscall_exit(tid, &r)) {
                int idx = thread_index(state, tid);
                if (idx >= 0) {
                    state->threads.data[idx].regs = r;   /* clean exit regs */
                    state->threads.data[idx].regs_valid = 1;
                    winner_idx = idx;
                    break;
                }
            }
            /* Entry stop (or unknown thread): let it proceed. */
            ptrace(PTRACE_SYSCALL, tid, 0, 0);
            continue;
        }

        /* PTRACE_EVENT stops (new thread via clone, etc.) and group-stops
         * (SIGSTOP/SIGTSTP) and plain SIGTRAP: resume without injecting a
         * signal.  This also safely handles a brand-new thread's initial
         * stop -- we just keep it running rather than forwarding a bogus
         * stop signal. */
        if (sig == SIGTRAP || sig == SIGSTOP || sig == SIGTSTP ||
            sig == SIGTTIN || sig == SIGTTOU || thread_index(state, tid) < 0) {
            ptrace(PTRACE_SYSCALL, tid, 0, 0);
            continue;
        }

        /* A real signal to a known thread: forward it so the application
         * behaves exactly as it would have without qcore present. */
        ptrace(PTRACE_SYSCALL, tid, 0, (void *)(long)sig);
    }

    alarm(0);
    sigaction(SIGALRM, &old_alarm, NULL);

    if (winner_idx < 0) {
        /* Timeout: freeze everyone so the caller can detach cleanly. */
        for (int i = 0; i < state->threads.count; i++) {
            if (state->threads.data[i].tid > 0)
                ptrace(PTRACE_INTERRUPT, state->threads.data[i].tid, 0, 0);
        }
        for (int i = 0; i < state->threads.count; i++) {
            pid_t tid = state->threads.data[i].tid;
            if (tid <= 0) continue;
            int st;
            if (waitpid(tid, &st, __WALL) > 0 && WIFSTOPPED(st))
                ptrace(PTRACE_GETREGS, tid, NULL, &state->threads.data[i].regs);
        }
        return -1;
    }

    /* Clear syscall-trace options on the winner before we inject: we are
     * about to PTRACE_SINGLESTEP an injected syscall on it, and leaving
     * PTRACE_O_TRACESYSGOOD set could make the step double-stop (a syscall
     * stop plus the singlestep trap), confusing exec_syscall_at. */
    ptrace(PTRACE_SETOPTIONS, state->threads.data[winner_idx].tid, 0, 0);

    /* Winner found and stopped at a clean exit; freeze the rest. */
    refreeze_others(state, state->threads.data[winner_idx].tid);
    printf("[phase2] race winner TID=%d at syscall-exit\n",
           (int)state->threads.data[winner_idx].tid);
    return winner_idx;
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

    /* Restore the EXACT original registers and let the kernel sort out
     * any pending syscall restart on detach (signr==0 path):
     *   - clean injector (user-space / syscall-exit): no restart code, the
     *     thread simply continues -- perfectly transparent.
     *   - force-mode mid-syscall injector: rax holds an ERESTART* code and
     *     the kernel transparently restarts the syscall.  (epoll_wait will
     *     already hold -EINTR, a benign value.)
     * We never rip-2 and never synthesise -EINTR. */
    ptrace(PTRACE_SETREGS, safe_tid, NULL,
           (struct user_regs_struct *)&state->safe_saved_regs);
    state->safe_bytes_modified = 0;
}

/* ------------------------------------------------------------------ */
/* Main entry point                                                    */

int inject_parasite(qcore_state_t *state)
{
    /* ---- 1. Select the injector thread ---------------------------- */
    /* Best case: a thread already in user-space.  Otherwise, in safe mode
     * race to a syscall-exit; in force mode hijack any thread. */
    int sidx = find_userspace_injector(state);
    const char *how = "user-space (clean)";
    if (sidx < 0) {
        if (!state->force) {
            int timeout = QCORE_RACE_TIMEOUT_SEC;
            const char *env = getenv("QCORE_RACE_TIMEOUT_SEC");
            if (env) { int v = atoi(env); if (v > 0) timeout = v; }
            sidx = race_for_injector(state, timeout);
            how = "syscall-exit (clean, via race)";
            if (sidx < 0) {
                fprintf(stderr,
                    "[inject] no thread reached a safe injection point within "
                    "%ds.\n          The target appears fully idle in blocking "
                    "syscalls.\n          Re-run with -f to force injection "
                    "(may surface a benign -EINTR).\n",
                    timeout);
                return -1;   /* race left all threads frozen; caller detaches */
            }
        } else {
            sidx = find_any_injector(state);
            how = "forced (-f; mid-syscall, kernel will restart)";
            if (sidx < 0) {
                fprintf(stderr, "[inject] no usable injection thread\n");
                return -1;
            }
        }
    }
    state->safe_thread_idx = sidx;

    pid_t safe_tid = state->threads.data[sidx].tid;
    uint64_t rip   = state->threads.data[sidx].regs.rip;
    state->safe_saved_regs = state->threads.data[sidx].regs;

    printf("[phase2] injector TID=%d  RIP=0x%llx  %s\n",
           (int)safe_tid, (unsigned long long)rip, how);

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

    /* ---- 6. Extract child PID from %rax -------------------------- */
    struct user_regs_struct trap_regs;
    if (ptrace(PTRACE_GETREGS, safe_tid, NULL, &trap_regs) == -1) {
        perror("GETREGS (trap)"); goto fail;
    }
    long long raw = (long long)trap_regs.rax;
    if (raw <= 0) {
        fprintf(stderr, "[inject] parasite clone() failed: errno=%lld\n",
                -raw);
        goto fail;
    }
    state->child_pid = (pid_t)raw;
    printf("[phase3] parasite complete - child PID=%d\n", (int)state->child_pid);

    /* ---- 7. Free parasite mapping + restore safe thread ---------- */
    double t_restore = qcore_now_ms();
    restore_safe_thread(state, safe_tid, rip);
    printf("[timing]  munmap + restore:   %.2f ms\n",
           qcore_now_ms() - t_restore);

    /* ---- 8. Detach all known threads ----------------------------- */
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

    /* ---- 9. Final sweep: detach threads born during the race ----- */
    /* During safe-mode's race, PTRACE_O_TRACECLONE auto-attaches any
     * thread the target spawns while we're watching.  Those threads are
     * NOT in state->threads and are not detached above.  When qcore
     * exits, every still-ptraced thread receives SIGKILL and becomes a
     * zombie under the target PID -- exactly the "two defunct processes"
     * symptom.  Scan /proc/<pid>/task and detach anything we missed.  */
    {
        char task_dir[64];
        snprintf(task_dir, sizeof(task_dir), "/proc/%d/task",
                 (int)state->target_pid);
        DIR *d = opendir(task_dir);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                if (ent->d_name[0] == '.') continue;
                pid_t tid = (pid_t)strtol(ent->d_name, NULL, 10);
                if (tid <= 0) continue;
                /* Skip threads we already handled. */
                int known = 0;
                for (int i = 0; i < state->threads.count; i++)
                    if (state->threads.data[i].tid == tid) { known = 1; break; }
                if (known) continue;
                /* Detach silently: if it was never ptraced this is ESRCH. */
                if (ptrace(PTRACE_DETACH, tid, NULL, NULL) == 0) {
                    fprintf(stderr, "[phase4] detached late-born TID=%d\n",
                            (int)tid);
                    detached++;
                }
            }
            closedir(d);
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

/* ------------------------------------------------------------------ */
/* Cleanup phase: make the target reap the dead child                  */

/*
 * The child is a direct child of the target.  After qcore kills it, it
 * becomes a zombie that only its parent -- the target -- can release.  qcore
 * is at most its tracer, which is not enough.  So we briefly re-attach to one
 * thread of the target and inject a wait4() on the child, causing the target
 * to reap its own zombie child.
 *
 * The injected wait4 runs inside the target's PID namespace, so it must use
 * the namespace-local PID (child_ns_pid), not the host PID.  __WALL is
 * required because the child was cloned with exit_signal=0.
 *
 * This is a second, very brief freeze (a single injected syscall on one
 * thread).  Any thread works: we restore its exact registers and detach, so
 * an interrupted syscall restarts transparently.
 */
int reap_child_in_target(qcore_state_t *state)
{
    /*
     * Re-seize ALL threads before injecting.
     *
     * The wait4 injection works by temporarily patching a syscall opcode
     * (0x0F 0x05) into the target's executable memory at the injected
     * thread's RIP -- which lives in shared library/binary code.  If any
     * OTHER thread were running, it could execute those patched bytes (or a
     * now-misaligned instruction) and take SIGILL.  Freezing every thread
     * for the duration of the injection closes that window, exactly as the
     * main parasite injection does.  (Freezing only one thread while the
     * others run is what crashes the target with SIGILL.)
     *
     * This is a second, brief freeze; no core I/O happens during it.
     */
    free(state->threads.data);
    memset(&state->threads, 0, sizeof(state->threads));
    if (seize_all_threads(state) != 0) {
        fprintf(stderr, "[phase7] re-seize failed; child may remain a zombie\n");
        return -1;
    }

    /* Prefer a user-space thread (cleanest restore); else any valid one. */
    int idx = find_userspace_injector(state);
    if (idx < 0)
        for (int i = 0; i < state->threads.count; i++)
            if (state->threads.data[i].regs_valid) { idx = i; break; }
    if (idx < 0) {
        fprintf(stderr, "[phase7] no thread to inject wait4 into\n");
        for (int i = 0; i < state->threads.count; i++)
            if (state->threads.data[i].tid > 0)
                ptrace(PTRACE_DETACH, state->threads.data[i].tid, NULL, NULL);
        return -1;
    }

    pid_t tid = state->threads.data[idx].tid;
    struct user_regs_struct saved = state->threads.data[idx].regs;

    /* Inject wait4(child_ns_pid, NULL, __WALL, NULL). */
    struct user_regs_struct r = saved;
    r.rax = 61;                          /* SYS_wait4              */
    r.rdi = (unsigned long long)state->child_ns_pid;
    r.rsi = 0;                           /* wstatus = NULL         */
    r.rdx = 0x40000000;                  /* __WALL                 */
    r.r10 = 0;                           /* rusage = NULL          */
    long ret = exec_syscall_at(tid, saved.rip, &r);

    if (ret == (long)state->child_ns_pid)
        printf("[phase7] target reaped child (ns pid %d)\n",
               (int)state->child_ns_pid);
    else
        fprintf(stderr, "[phase7] wait4 in target returned %ld "
                "(child may already be reaped)\n", ret);

    /* Restore the injected thread's exact registers. */
    ptrace(PTRACE_SETREGS, tid, NULL, &saved);

    /* Detach all threads.  The injected thread is back to its saved state;
     * any thread interrupted in an ERESTART* syscall restarts transparently
     * on detach (signr==0 path). */
    for (int i = 0; i < state->threads.count; i++) {
        pid_t t = state->threads.data[i].tid;
        if (t > 0) ptrace(PTRACE_DETACH, t, NULL, NULL);
    }
    return 0;
}
