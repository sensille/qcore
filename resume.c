/*
 * Phase 4 – Restore the injected thread and detach from all parent threads.
 *
 * After detachment the target process is fully running again.  The COW child
 * stays in ptrace-stop as our tracee; we do NOT detach it here.
 */
#include "qcore.h"

int resume_parent(qcore_state_t *state)
{
    pid_t injector_tid = state->threads.data[state->injector_idx].tid;

    /* ---- Restore the original bytes at RIP ---- */
    if (ptrace(PTRACE_POKETEXT, injector_tid,
               (void *)state->injector_saved_regs.rip,
               (void *)(unsigned long)state->injector_saved_word) == -1) {
        perror("PTRACE_POKETEXT (restore)");
        return -1;
    }

    /* ---- Restore original registers ---- */
    if (ptrace(PTRACE_SETREGS, injector_tid, NULL,
               &state->injector_saved_regs) == -1) {
        perror("PTRACE_SETREGS (restore)");
        return -1;
    }

    /* ---- Detach all parent threads ---- */
    int detached = 0;
    for (int i = 0; i < state->threads.count; i++) {
        pid_t tid = state->threads.data[i].tid;
        if (ptrace(PTRACE_DETACH, tid, NULL, NULL) == -1) {
            if (errno == ESRCH) continue;   /* already gone */
            fprintf(stderr, "PTRACE_DETACH(%d): %s\n",
                    (int)tid, strerror(errno));
        } else {
            detached++;
        }
    }

    printf("[phase4] parent process running again – detached %d thread(s)\n",
           detached);
    /*
     * The child (state->child_pid) remains in ptrace-stop as our tracee.
     * We do NOT detach it; Phase 5 reads its memory via /proc/child/mem.
     */
    return 0;
}
