/*
 * Phase 4 - Restore the injected thread and detach from all parent threads.
 *
 * Key goal: make the freeze completely transparent to the target.
 *
 * When PTRACE_SEIZE + PTRACE_INTERRUPT stops a thread in a blocking
 * syscall, the kernel stores a restart code in rax:
 *
 *   ERESTARTSYS           = -512
 *   ERESTARTNOINTR        = -513
 *   ERESTARTNOHAND        = -514  (e.g. epoll_wait, io_uring_enter)
 *   ERESTART_RESTARTBLOCK = -516
 *
 * For non-injector threads, arch_do_signal_or_restart() fires on
 * PTRACE_DETACH (TIF_SIGPENDING from PTRACE_INTERRUPT) and restarts
 * ERESTARTSYS/ERESTARTNOINTR transparently.  ERESTARTNOHAND gets
 * converted to -EINTR by the kernel.
 *
 * For the INJECTOR thread, executing clone() via PTRACE_SINGLESTEP
 * cleared the kernel's restart-pending task flags, so the restart
 * machinery is bypassed entirely.  We must fix rax explicitly.
 *
 * Rather than converting to -EINTR (which propagates to application
 * code), we rewind the thread to re-execute its original blocking
 * syscall: set rip = saved_rip - 2 (back to the 2-byte syscall
 * instruction on x86-64) and rax = orig_rax (the syscall number).
 * The thread re-enters the call as if qcore never ran.
 *
 * We apply the same rewind to non-injector ERESTARTNOHAND threads
 * (which the kernel would otherwise force to return -EINTR) so that
 * ALL threads are completely transparent.
 */
#include "qcore.h"

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
 * Rewind r to re-execute its interrupted syscall.
 * Returns 1 if registers were modified, 0 otherwise.
 */
static int prepare_syscall_restart(struct user_regs_struct *r)
{
    if (r->orig_rax == (unsigned long long)-1)
        return 0;
    if (!is_restart_code((long long)r->rax))
        return 0;
    r->rip -= 2;
    r->rax  = r->orig_rax;
    return 1;
}

int resume_parent(qcore_state_t *state)
{
    pid_t injector_tid = state->threads.data[state->injector_idx].tid;

    /* Restore original bytes at RIP. */
    if (ptrace(PTRACE_POKETEXT, injector_tid,
               (void *)state->injector_saved_regs.rip,
               (void *)(unsigned long)state->injector_saved_word) == -1) {
        perror("PTRACE_POKETEXT (restore)");
        return -1;
    }

    /* Restore injector registers, rewinding to re-enter the original syscall. */
    struct user_regs_struct inj_regs = state->injector_saved_regs;
    prepare_syscall_restart(&inj_regs);
    if (ptrace(PTRACE_SETREGS, injector_tid, NULL, &inj_regs) == -1) {
        perror("PTRACE_SETREGS (restore)");
        return -1;
    }

    state->injector_bytes_modified = 0;

    /* Detach all threads, rewinding any interrupted syscall first. */
    int detached = 0;
    for (int i = 0; i < state->threads.count; i++) {
        pid_t tid = state->threads.data[i].tid;

        if (i != state->injector_idx && state->threads.data[i].regs_valid) {
            struct user_regs_struct r = state->threads.data[i].regs;
            if (prepare_syscall_restart(&r))
                ptrace(PTRACE_SETREGS, tid, NULL, &r);
        }

        if (ptrace(PTRACE_DETACH, tid, NULL, NULL) == -1) {
            if (errno == ESRCH) continue;
            fprintf(stderr, "PTRACE_DETACH(%d): %s\n",
                    (int)tid, strerror(errno));
        } else {
            detached++;
        }
    }

    printf("[phase4] parent process running again - detached %d thread(s)\n",
           detached);
    return 0;
}
