/*
 * Phase 3 – COW clone via fork() syscall injection.
 *
 * We pick the main thread (TID == PID) as the injector, arm it with
 * PTRACE_O_TRACEFORK, overwrite the two bytes at RIP with the x86-64
 * "syscall" opcode (0x0F 0x05), set RAX=57 (sys_fork), single-step it,
 * catch the PTRACE_EVENT_FORK notification, and record the child PID.
 *
 * After this phase the parent is still frozen; the child is in ptrace-stop
 * as a new tracee of this process.
 */
#include "qcore.h"

/* x86-64 "syscall" instruction: two bytes */
#define SYSCALL_OPCODE   0x050FULL    /* little-endian: byte[0]=0x0F byte[1]=0x05 */
#define SYSCALL_OPCODE_MASK 0xFFFFULL
#define SYS_FORK         57ULL

static int find_injector(qcore_state_t *state)
{
    /* Prefer the main thread (TID == PID); fall back to first valid thread. */
    for (int i = 0; i < state->threads.count; i++) {
        if (state->threads.data[i].tid == state->target_pid &&
            state->threads.data[i].regs_valid)
            return i;
    }
    for (int i = 0; i < state->threads.count; i++) {
        if (state->threads.data[i].regs_valid)
            return i;
    }
    return -1;
}

int cow_clone(qcore_state_t *state)
{
    int idx = find_injector(state);
    if (idx < 0) {
        fprintf(stderr, "[cow_clone] no valid thread to inject into\n");
        return -1;
    }
    state->injector_idx = idx;

    pid_t injector_tid = state->threads.data[idx].tid;
    struct user_regs_struct *regs = &state->threads.data[idx].regs;

    printf("[phase3] injector TID=%d  RIP=0x%llx\n",
           (int)injector_tid, (unsigned long long)regs->rip);

    /* Save original registers for restoration in Phase 4. */
    state->injector_saved_regs = *regs;

    /* ---- Set PTRACE_O_TRACEFORK on injector ---- */
    if (ptrace(PTRACE_SETOPTIONS, injector_tid, 0,
               (void *)(long)PTRACE_O_TRACEFORK) == -1) {
        perror("PTRACE_SETOPTIONS TRACEFORK");
        return -1;
    }

    /* ---- Save the 8-byte word at RIP ---- */
    errno = 0;
    unsigned long saved_word = ptrace(PTRACE_PEEKTEXT, injector_tid,
                                      (void *)regs->rip, NULL);
    if (errno != 0) {
        fprintf(stderr, "PTRACE_PEEKTEXT at 0x%llx: %s\n",
                (unsigned long long)regs->rip, strerror(errno));
        return -1;
    }
    state->injector_saved_word = (uint64_t)saved_word;

    /* ---- Overwrite first two bytes with "syscall" ---- */
    unsigned long new_word = (saved_word & ~(unsigned long)SYSCALL_OPCODE_MASK)
                             | (unsigned long)SYSCALL_OPCODE;
    if (ptrace(PTRACE_POKETEXT, injector_tid,
               (void *)regs->rip, (void *)new_word) == -1) {
        perror("PTRACE_POKETEXT (inject syscall)");
        return -1;
    }

    /* ---- Modify registers: RAX=SYS_fork, keep RIP as-is ---- */
    struct user_regs_struct mod_regs = *regs;
    mod_regs.rax = SYS_FORK;
    if (ptrace(PTRACE_SETREGS, injector_tid, NULL, &mod_regs) == -1) {
        perror("PTRACE_SETREGS");
        return -1;
    }

    /* ---- Single-step: execute the injected syscall ---- */
    if (ptrace(PTRACE_SINGLESTEP, injector_tid, 0, 0) == -1) {
        perror("PTRACE_SINGLESTEP");
        return -1;
    }

    /*
     * Wait for injector to stop.  If PTRACE_O_TRACEFORK is active and the
     * syscall was sys_fork, we expect a PTRACE_EVENT_FORK stop.  Accept
     * ordinary SIGTRAP stops too (some kernels deliver an extra single-step
     * trap before the fork event).
     */
    pid_t child_pid = -1;
    for (int tries = 0; tries < 8; tries++) {
        int status = 0;
        pid_t who = waitpid(injector_tid, &status, __WALL);
        if (who == -1) {
            perror("waitpid (singlestep)");
            return -1;
        }

        if (!WIFSTOPPED(status)) {
            fprintf(stderr, "[cow_clone] unexpected status 0x%x after singlestep\n", status);
            return -1;
        }

        /* Check for PTRACE_EVENT_FORK */
        if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) {
            unsigned long cpid = 0;
            if (ptrace(PTRACE_GETEVENTMSG, injector_tid, 0, &cpid) == -1) {
                perror("PTRACE_GETEVENTMSG");
                return -1;
            }
            child_pid = (pid_t)cpid;
            printf("[phase3] fork() injected – child PID=%d\n", (int)child_pid);
            break;
        }

        /* Ordinary single-step SIGTRAP – keep stepping until fork event */
        if (WSTOPSIG(status) == SIGTRAP) {
            if (ptrace(PTRACE_SINGLESTEP, injector_tid, 0, 0) == -1) {
                perror("PTRACE_SINGLESTEP (retry)");
                return -1;
            }
            continue;
        }

        fprintf(stderr, "[cow_clone] unexpected stop signal %d\n", WSTOPSIG(status));
        return -1;
    }

    if (child_pid < 0) {
        fprintf(stderr, "[cow_clone] did not receive PTRACE_EVENT_FORK\n");
        return -1;
    }

    /* Consume the child's initial ptrace-stop. */
    int child_status = 0;
    if (waitpid(child_pid, &child_status, __WALL) == -1) {
        perror("waitpid (child initial stop)");
        return -1;
    }
    if (!WIFSTOPPED(child_status)) {
        fprintf(stderr, "[cow_clone] child not in stopped state (0x%x)\n", child_status);
        return -1;
    }

    state->child_pid = child_pid;
    printf("[phase3] COW snapshot ready – child PID=%d is frozen\n", (int)child_pid);
    return 0;
}
