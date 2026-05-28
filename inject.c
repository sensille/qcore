/*
 * inject.c - Phases 2-4: parasite injection, execution, and teardown.
 *
 * Phase 2: Find (or create) a safe injection point in the target, then
 *          inject an mmap syscall to allocate 3 pages for the parasite.
 *
 * Phase 3: Write the parasite shellcode into the code page and let it
 *          run natively.  It performs the stealth double-fork internally
 *          and signals completion via int3.
 *
 * Phase 4: Catch the int3 trap, read child2_pid from %rax, inject munmap
 *          to free the parasite pages, restore the safe thread's original
 *          registers (using the rip-2 restart trick if needed), and
 *          PTRACE_DETACH every thread.
 *
 * The "safe thread" is a thread that was executing in user-space
 * (orig_rax == -1) when ptrace stopped it.  Injection into such a thread
 * needs no restart-code fixup on restore.  If no user-space thread exists
 * we step one thread forward with PTRACE_SYSCALL until it exits a syscall,
 * which also gives a clean injection point.
 */

#include "qcore.h"
#include "parasite.h"   /* parasite_bin[], parasite_bin_len */

/* Parasite page layout within the 3-page mmap allocation. */
#define PARASITE_PAGES       3
#define PARASITE_MMAP_SIZE   (PARASITE_PAGES * 4096)
#define SCRATCH_OFF          0        /* page 0: u64 child2_pid at offset 0 */
#define CHILD1_STACK_OFF     4096     /* page 1: Child 1's stack            */
#define CHILD1_STACK_TOP     8176     /* top of page 1 (16-byte aligned)    */
#define CODE_OFF             8192     /* page 2: shellcode                  */

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
 * Execute a single syscall in tid's context at the given rip.
 * Saves and restores the 8 bytes at rip around the injection.
 * mod_regs must have all syscall arguments set; its rip is overridden.
 * Returns the (signed) syscall return value, or LONG_MIN on ptrace error.
 */
static long exec_syscall_at(pid_t tid, uint64_t rip,
                             struct user_regs_struct *mod_regs)
{
    /* Save original bytes at rip. */
    errno = 0;
    unsigned long orig = ptrace(PTRACE_PEEKTEXT, tid, (void *)rip, NULL);
    if (errno) { perror("PEEKTEXT"); return LONG_MIN; }

    /* Write syscall opcode 0x0F 0x05. */
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

    /* Restore original bytes. */
    if (ptrace(PTRACE_POKETEXT, tid, (void *)rip, (void *)orig) == -1) {
        perror("POKETEXT restore"); return LONG_MIN;
    }

    return result;
}

/*
 * Write a byte array into tid's address space using PTRACE_POKETEXT.
 * addr must be writable (i.e. inside the mmap'd RWX region).
 */
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
        /* Partial last word: read-modify-write. */
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
 * Select the injection thread.
 *
 * Priority:
 *   1. Non-main thread in user-space (orig_rax == -1): completely clean,
 *      no rip-2 fixup needed on restore.
 *   2. Main thread in user-space: clean but riskier for event loops.
 *   3. Non-main thread in a blocking syscall: rip-2 will transparently
 *      restart the syscall on detach.  Worker threads (futex_wait, etc.)
 *      handle spurious restarts correctly via pthreads.
 *   4. Main thread in a blocking syscall: last resort.
 *
 * Why NOT use PTRACE_SYSCALL to advance threads to a syscall-exit boundary:
 *   PTRACE_SYSCALL interacts badly with PTRACE_SINGLESTEP -- the kernel
 *   emits BOTH a syscall-exit stop and a singlestep SIGTRAP, so exec_syscall_at
 *   consumes the wrong event and the subsequent int3 waitpid catches a stale
 *   singlestep stop instead of the real trap.  The rip-2 approach already
 *   handles syscall-blocked threads correctly without this complexity.
 */
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
    for (int i = 0; i < state->threads.count; i++) {
        const thread_info_t *t = &state->threads.data[i];
        if (t->regs_valid && t->tid != main_tid) return i;
    }
    for (int i = 0; i < state->threads.count; i++) {
        if (state->threads.data[i].regs_valid) return i;
    }
    return -1;
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

    int in_user = (state->threads.data[sidx].regs.orig_rax == (unsigned long long)-1);
    printf("[phase2] safe thread TID=%d  RIP=0x%llx  %s\n",
           (int)safe_tid, (unsigned long long)rip,
           in_user ? "(was in user-space - clean injection point)"
                   : "(was in syscall - rip-2 restart on detach)");

    /* ---- 2. Allocate parasite pages via injected mmap ------------ */
    struct user_regs_struct mmap_regs = state->safe_saved_regs;
    mmap_regs.rax = 9;           /* SYS_mmap                      */
    mmap_regs.rdi = 0;           /* addr = NULL                   */
    mmap_regs.rsi = PARASITE_MMAP_SIZE;
    mmap_regs.rdx = 7;           /* PROT_READ | PROT_WRITE | PROT_EXEC */
    mmap_regs.r10 = 0x22;        /* MAP_PRIVATE | MAP_ANONYMOUS   */
    mmap_regs.r8  = (unsigned long long)-1;   /* fd = -1          */
    mmap_regs.r9  = 0;           /* offset = 0                    */

    state->safe_bytes_modified = 1;
    long mmap_ret = exec_syscall_at(safe_tid, rip, &mmap_regs);
    state->safe_bytes_modified = 0;
    if (mmap_ret == LONG_MIN || mmap_ret < 0) {
        fprintf(stderr, "[inject] mmap failed: %ld\n", mmap_ret);
        return -1;
    }
    state->mmap_addr = (uint64_t)mmap_ret;
    printf("[phase2] parasite mapped at 0x%llx (%d bytes)\n",
           (unsigned long long)state->mmap_addr, PARASITE_MMAP_SIZE);

    /* ---- 3. Write parasite shellcode into code page -------------- */
    uint64_t code_addr = state->mmap_addr + CODE_OFF;
    if ((int)parasite_bin_len > 4096) {
        fprintf(stderr, "[inject] parasite too large (%u bytes)\n",
                parasite_bin_len);
        return -1;
    }
    if (poke_bytes(safe_tid, code_addr,
                   parasite_bin, parasite_bin_len) < 0)
        return -1;

    printf("[phase2] parasite written (%u bytes at 0x%llx)\n",
           parasite_bin_len, (unsigned long long)code_addr);

    /* ---- 4. Run parasite ----------------------------------------- */
    struct user_regs_struct run_regs = state->safe_saved_regs;
    run_regs.rip = code_addr;
    run_regs.r15 = state->mmap_addr;   /* scratch/stack/code base */
    /* Clear rax so the first 'test rax,rax' after clone returns cleanly. */
    run_regs.rax = 0;

    if (ptrace(PTRACE_SETREGS, safe_tid, NULL, &run_regs) == -1) {
        perror("SETREGS (run parasite)"); return -1;
    }
    if (ptrace(PTRACE_CONT, safe_tid, 0, 0) == -1) {
        perror("PTRACE_CONT (run parasite)"); return -1;
    }

    /* ---- 5. Wait for int3 from the parasite ---------------------- */
    int status;
    for (;;) {
        pid_t who = waitpid(safe_tid, &status, __WALL);
        if (who == -1) { perror("waitpid (parasite)"); return -1; }
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) break;
        if (WIFSTOPPED(status)) {
            /* Deliver any non-trap signal transparently. */
            if (ptrace(PTRACE_CONT, safe_tid, 0,
                       (void *)(long)WSTOPSIG(status)) == -1) {
                perror("PTRACE_CONT (signal)"); return -1;
            }
            continue;
        }
        fprintf(stderr, "[inject] unexpected waitpid status 0x%x\n", status);
        return -1;
    }

    /* ---- 6. Extract child2_pid from %rax ------------------------- */
    struct user_regs_struct trap_regs;
    if (ptrace(PTRACE_GETREGS, safe_tid, NULL, &trap_regs) == -1) {
        perror("GETREGS (trap)"); return -1;
    }
    pid_t child2 = (pid_t)trap_regs.rax;
    if (child2 <= 0) {
        fprintf(stderr, "[inject] bad child2_pid=%d from parasite\n",
                (int)child2);
        return -1;
    }
    state->child2_pid = child2;
    printf("[phase3] parasite complete - child2 PID=%d\n", (int)child2);

    /* ---- 7. Inject munmap to free parasite pages ----------------- */
    struct user_regs_struct unmap_regs = state->safe_saved_regs;
    unmap_regs.rax = 11;          /* SYS_munmap                   */
    unmap_regs.rdi = state->mmap_addr;
    unmap_regs.rsi = PARASITE_MMAP_SIZE;

    state->safe_bytes_modified = 1;
    long unmap_ret = exec_syscall_at(safe_tid, rip, &unmap_regs);
    state->safe_bytes_modified = 0;
    if (unmap_ret == LONG_MIN || unmap_ret < 0)
        fprintf(stderr, "[inject] munmap warning: %ld\n", unmap_ret);

    state->mmap_addr = 0;

    /* ---- 8. Restore safe thread to original state ---------------- */
    struct user_regs_struct restore_regs = state->safe_saved_regs;

    /* Apply rip-2 restart only if needed (syscall-blocked threads).
     * For user-space threads (orig_rax == -1) this is a no-op. */
    if (restore_regs.orig_rax != (unsigned long long)-1 &&
        is_restart_code((long long)restore_regs.rax)) {
        restore_regs.rip -= 2;
        restore_regs.rax  = restore_regs.orig_rax;
    }
    if (ptrace(PTRACE_SETREGS, safe_tid, NULL, &restore_regs) == -1) {
        perror("SETREGS (restore safe thread)"); return -1;
    }

    /* ---- 9. Detach all parent threads with transparent restart --- */
    int detached = 0;
    for (int i = 0; i < state->threads.count; i++) {
        pid_t tid = state->threads.data[i].tid;
        if (tid <= 0) continue;

        if (i != sidx && state->threads.data[i].regs_valid) {
            /* For non-safe threads: apply rip-2 restart for restart codes.
             * The kernel's arch_do_signal_or_restart also handles
             * ERESTARTSYS/ERESTARTNOINTR, but is explicit here for
             * ERESTARTNOHAND (epoll_wait, io_uring_enter, etc.) which
             * the kernel would otherwise force to -EINTR. */
            struct user_regs_struct r = state->threads.data[i].regs;
            if (r.orig_rax != (unsigned long long)-1 &&
                is_restart_code((long long)r.rax)) {
                r.rip -= 2;
                r.rax  = r.orig_rax;
                ptrace(PTRACE_SETREGS, tid, NULL, &r);
            }
        }

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
