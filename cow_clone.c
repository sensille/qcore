/*
 * Phase 3 - COW clone via clone() syscall injection.
 *
 * We use sys_clone(CLONE_FILES) rather than sys_fork() for two reasons:
 *
 * 1. CLONE_FILES shares the parent's fd table so no individual fds are
 *    closed when the child exits (prevents delayed socket RST/FIN).
 *
 * 2. exit_signal = CLONE_FILES & 0xFF = 0, so no SIGCHLD to the parent.
 *
 * We prefer non-main threads as the injector to avoid disrupting the
 * application's event loop.  The injector's interrupted syscall is
 * restarted transparently in resume.c via the rip-2 trick.
 */
#include "qcore.h"

#define SYSCALL_OPCODE      0x050FULL
#define SYSCALL_OPCODE_MASK 0xFFFFULL
#define SYS_CLONE_NR        56ULL
#define CLONE_FILES_FLAG    0x00000400UL

/*
 * Priority:
 *  1. Non-main thread not in a syscall  (cleanest injection point)
 *  2. Main thread not in a syscall
 *  3. Non-main thread in a syscall      (worker; pthreads handles -EINTR)
 *  4. Main thread in a syscall          (last resort)
 */
static int find_injector(qcore_state_t *state)
{
    pid_t main_tid = state->target_pid;

    for (int i = 0; i < state->threads.count; i++) {
        thread_info_t *t = &state->threads.data[i];
        if (!t->regs_valid || t->tid == main_tid) continue;
        if (t->regs.orig_rax == (unsigned long long)-1)
            return i;
    }
    for (int i = 0; i < state->threads.count; i++) {
        thread_info_t *t = &state->threads.data[i];
        if (!t->regs_valid || t->tid != main_tid) continue;
        if (t->regs.orig_rax == (unsigned long long)-1)
            return i;
    }
    for (int i = 0; i < state->threads.count; i++) {
        thread_info_t *t = &state->threads.data[i];
        if (t->regs_valid && t->tid != main_tid)
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

    int in_syscall = (regs->orig_rax != (unsigned long long)-1);
    printf("[phase3] injector TID=%d  RIP=0x%llx  %s\n",
           (int)injector_tid,
           (unsigned long long)regs->rip,
           in_syscall ? "(was in syscall)" : "(was in user-space)");

    state->injector_saved_regs = *regs;

    if (ptrace(PTRACE_SETOPTIONS, injector_tid, 0,
               (void *)(long)(PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK)) == -1) {
        perror("PTRACE_SETOPTIONS TRACECLONE|TRACEFORK");
        return -1;
    }

    errno = 0;
    unsigned long saved_word = ptrace(PTRACE_PEEKTEXT, injector_tid,
                                      (void *)regs->rip, NULL);
    if (errno != 0) {
        fprintf(stderr, "PTRACE_PEEKTEXT at 0x%llx: %s\n",
                (unsigned long long)regs->rip, strerror(errno));
        return -1;
    }
    state->injector_saved_word = (uint64_t)saved_word;

    state->injector_bytes_modified = 1;
    unsigned long new_word = (saved_word & ~(unsigned long)SYSCALL_OPCODE_MASK)
                             | (unsigned long)SYSCALL_OPCODE;
    if (ptrace(PTRACE_POKETEXT, injector_tid,
               (void *)regs->rip, (void *)new_word) == -1) {
        perror("PTRACE_POKETEXT (inject syscall)");
        return -1;
    }

    struct user_regs_struct mod_regs = *regs;
    mod_regs.rax = SYS_CLONE_NR;
    mod_regs.rdi = CLONE_FILES_FLAG;
    mod_regs.rsi = 0;
    mod_regs.rdx = 0;
    mod_regs.r10 = 0;
    mod_regs.r8  = 0;
    if (ptrace(PTRACE_SETREGS, injector_tid, NULL, &mod_regs) == -1) {
        perror("PTRACE_SETREGS");
        return -1;
    }

    if (ptrace(PTRACE_SINGLESTEP, injector_tid, 0, 0) == -1) {
        perror("PTRACE_SINGLESTEP");
        return -1;
    }

    pid_t child_pid = -1;
    for (int tries = 0; tries < 8; tries++) {
        int status = 0;
        if (waitpid(injector_tid, &status, __WALL) == -1) {
            perror("waitpid (singlestep)");
            return -1;
        }

        if (!WIFSTOPPED(status)) {
            fprintf(stderr, "[cow_clone] unexpected status 0x%x\n", status);
            return -1;
        }

        int ev = status >> 8;
        if (ev == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)) ||
            ev == (SIGTRAP | (PTRACE_EVENT_FORK  << 8))) {
            unsigned long cpid = 0;
            if (ptrace(PTRACE_GETEVENTMSG, injector_tid, 0, &cpid) == -1) {
                perror("PTRACE_GETEVENTMSG");
                return -1;
            }
            child_pid = (pid_t)cpid;
            printf("[phase3] clone() injected - child PID=%d\n", (int)child_pid);
            break;
        }

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
        fprintf(stderr, "[cow_clone] did not receive PTRACE_EVENT_CLONE/FORK\n");
        return -1;
    }

    int child_status = 0;
    if (waitpid(child_pid, &child_status, __WALL) == -1) {
        perror("waitpid (child initial stop)");
        return -1;
    }
    if (!WIFSTOPPED(child_status)) {
        fprintf(stderr, "[cow_clone] child not stopped (0x%x)\n", child_status);
        return -1;
    }

    state->child_pid = child_pid;
    printf("[phase3] COW snapshot ready - child PID=%d is frozen\n", (int)child_pid);
    return 0;
}
