/*
 * qcore - zero-pause core dumper for Linux x86-64
 *
 * Usage: qcore <pid>
 *
 * Produces:
 *   core.<pid>               ELF64 core loadable by gdb/lldb
 *   core.<pid>.sockets.json  socket and FD inventory
 *
 * Must run as root or with CAP_SYS_PTRACE.
 *
 * Phase overview
 * --------------
 * 1  Seize all threads with PTRACE_SEIZE + PTRACE_INTERRUPT (no SIGSTOP)
 *    and harvest GP registers for the ELF PT_NOTE section.
 * 2  Find a safe injection thread (user-space or syscall-exit boundary).
 *    Inject mmap to allocate the parasite pages, write the shellcode.
 * 3  The parasite runs natively inside the target:
 *      clone(CLONE_VM) -> Child 1 (shares address space)
 *      Child 1: clone(0) -> Child 2 (COW snapshot), write child2_pid,
 *               close fds 0-1023, SIGSTOP, exit
 *      Parent:  spin on scratch page, int3 when child2_pid is visible
 * 4  Catch int3, read child2_pid, inject munmap, restore safe thread,
 *    PTRACE_DETACH all threads.  Target is now fully running again.
 * 5  PTRACE_ATTACH child2 (orphaned, SIGSTOP'd), build ELF core from
 *    /proc/child2/maps and /proc/child2/mem.
 * 6  SIGKILL child2 (fd-scrubbed => no side effects).
 */
#include "qcore.h"

/* -- Emergency signal handler ---------------------------------------- */

static volatile qcore_state_t *g_state;

static void emergency_cleanup(int sig)
{
    (void)sig;
    qcore_state_t *s = (qcore_state_t *)g_state;
    if (!s) _exit(1);

    /* If we modified bytes at the safe thread's RIP, restore them. */
    if (s->safe_bytes_modified && s->safe_thread_idx >= 0) {
        pid_t tid = s->threads.data[s->safe_thread_idx].tid;
        ptrace(PTRACE_POKETEXT, tid,
               (void *)s->safe_saved_regs.rip,
               (void *)(unsigned long)s->safe_saved_word);
        ptrace(PTRACE_SETREGS, tid, NULL,
               (struct user_regs_struct *)&s->safe_saved_regs);
    }

    /* Detach all parent threads. */
    for (int i = 0; i < s->threads.count; i++) {
        pid_t tid = s->threads.data[i].tid;
        if (tid > 0) ptrace(PTRACE_DETACH, tid, NULL, NULL);
    }

    /* Kill child2 if it exists. */
    if (s->child2_pid > 0) {
        kill(s->child2_pid, SIGKILL);
        waitpid(s->child2_pid, NULL, __WALL);
    }

    static const char msg[] = "qcore: interrupted - target detached\n";
    if (write(STDERR_FILENO, msg, sizeof(msg) - 1)) {}
    _exit(1);
}

/* -- Entry point ------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <pid>\n", prog);
}

static void check_alive(pid_t pid, const char *label)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    if (access(path, F_OK) != 0)
        fprintf(stderr, "[diag] target PID %d DEAD after %s\n",
                (int)pid, label);
}

int main(int argc, char *argv[])
{
    if (argc != 2) { usage(argv[0]); return 1; }

    pid_t pid = (pid_t)((int)strtol(argv[1], NULL, 10));
    if (pid <= 0) {
        fprintf(stderr, "Invalid PID: %s\n", argv[1]);
        return 1;
    }

    char proc_dir[64];
    snprintf(proc_dir, sizeof(proc_dir), "/proc/%d", (int)pid);
    struct stat st;
    if (stat(proc_dir, &st) != 0) {
        fprintf(stderr, "Process %d not found: %s\n", (int)pid, strerror(errno));
        return 1;
    }

    qcore_state_t state;
    memset(&state, 0, sizeof(state));
    state.target_pid       = pid;
    state.child2_pid       = -1;
    state.safe_thread_idx  = -1;
    snprintf(state.core_path,         sizeof(state.core_path),
             "core.%d", (int)pid);
    snprintf(state.sockets_json_path, sizeof(state.sockets_json_path),
             "core.%d.sockets.json", (int)pid);

    g_state = &state;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = emergency_cleanup;
    sigfillset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);

    printf("qcore: targeting PID %d\n", (int)pid);
    printf("  core:    %s\n", state.core_path);
    printf("  sockets: %s\n", state.sockets_json_path);

    /* Phase 1: Seize ------------------------------------------------ */
    if (seize_all_threads(&state) != 0) {
        fprintf(stderr, "Phase 1 failed\n");
        return 1;
    }
    check_alive(pid, "phase1");

    /* Phase 2 (FD harvest, concurrent with frozen state) ------------ */
    harvest_fds(&state);
    check_alive(pid, "phase2");

    /* Phases 2-4: inject parasite, run, detach ---------------------- */
    if (inject_parasite(&state) != 0) {
        fprintf(stderr, "Parasite injection failed - emergency detach\n");
        for (int i = 0; i < state.threads.count; i++)
            ptrace(PTRACE_DETACH, state.threads.data[i].tid, NULL, NULL);
        return 1;
    }
    check_alive(pid, "phase4");

    /* Phase 5: attach child2, build ELF ----------------------------- */
    /* child2 is orphaned (reparented to init) and waiting on SIGSTOP. */
    if (ptrace(PTRACE_ATTACH, state.child2_pid, NULL, NULL) == -1) {
        perror("PTRACE_ATTACH child2");
        kill(state.child2_pid, SIGKILL);
        return 1;
    }
    int ws2;
    if (waitpid(state.child2_pid, &ws2, 0) == -1) {
        perror("waitpid child2");
        kill(state.child2_pid, SIGKILL);
        return 1;
    }

    write_sockets_json(&state);

    int dump_ok = dump_core(&state);
    if (dump_ok != 0)
        fprintf(stderr, "Phase 5 (core dump) failed\n");
    check_alive(pid, "phase5");

    /* Phase 6: kill child2 ------------------------------------------ */
    kill(state.child2_pid, SIGKILL);
    waitpid(state.child2_pid, NULL, __WALL);
    printf("[phase6] child2 (PID=%d) killed\n", (int)state.child2_pid);
    check_alive(pid, "phase6");

    free(state.threads.data);
    free(state.fds.data);

    return dump_ok == 0 ? 0 : 1;
}
