/*
 * qcore - Instant Core GDB Loader
 *
 * Usage: qcore <pid>
 *
 * Produces:
 *   core.<pid>          - ELF64 core file loadable by gdb/lldb
 *   core.<pid>.sockets.json - socket/FD inventory of the target
 *
 * Must be run as root or with CAP_SYS_PTRACE.
 */
#include "qcore.h"

/* -- Emergency signal handler -------------------------------------------- */

static volatile qcore_state_t *g_state;

static void emergency_cleanup(int sig)
{
    (void)sig;
    qcore_state_t *s = (qcore_state_t *)g_state;
    if (!s) _exit(1);

    if (s->injector_bytes_modified && s->injector_idx >= 0) {
        pid_t tid = s->threads.data[s->injector_idx].tid;
        ptrace(PTRACE_POKETEXT, tid,
               (void *)s->injector_saved_regs.rip,
               (void *)(unsigned long)s->injector_saved_word);
        ptrace(PTRACE_SETREGS, tid, NULL,
               (struct user_regs_struct *)&s->injector_saved_regs);
    }

    for (int i = 0; i < s->threads.count; i++) {
        pid_t tid = s->threads.data[i].tid;
        if (tid > 0)
            ptrace(PTRACE_DETACH, tid, NULL, NULL);
    }

    if (s->child_pid > 0) {
        kill(s->child_pid, SIGKILL);
        waitpid(s->child_pid, NULL, __WALL);
    }

    static const char msg[] = "qcore: interrupted - target detached\n";
    if (write(STDERR_FILENO, msg, sizeof(msg) - 1)) {}
    _exit(1);
}

/* -- Entry point --------------------------------------------------------- */

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <pid>\n", prog);
}

static void check_alive(pid_t pid, const char *after)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    if (access(path, F_OK) != 0)
        fprintf(stderr, "[diag] target PID %d is DEAD after %s\n",
                (int)pid, after);
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
    state.target_pid   = pid;
    state.child_pid    = -1;
    state.injector_idx = -1;
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
    printf("  output core:    %s\n", state.core_path);
    printf("  output sockets: %s\n", state.sockets_json_path);

    /* -- Phase 1: Seize all threads ------------------------------- */
    if (seize_all_threads(&state) != 0) {
        fprintf(stderr, "Phase 1 failed\n");
        return 1;
    }
    check_alive(pid, "phase1");

    /* -- Phase 2: Harvest FD / socket info ------------------------ */
    if (harvest_fds(&state) != 0) {
        fprintf(stderr, "Phase 2 failed\n");
    }
    check_alive(pid, "phase2");

    /* -- Phase 3: COW clone via injected clone() ------------------- */
    if (cow_clone(&state) != 0) {
        fprintf(stderr, "Phase 3 failed - detaching and exiting\n");
        for (int i = 0; i < state.threads.count; i++)
            ptrace(PTRACE_DETACH, state.threads.data[i].tid, NULL, NULL);
        return 1;
    }
    check_alive(pid, "phase3");

    /* -- Phase 4: Resume parent ------------------------------------ */
    if (resume_parent(&state) != 0) {
        fprintf(stderr, "Phase 4 failed\n");
        if (state.child_pid > 0) kill(state.child_pid, SIGKILL);
        return 1;
    }
    check_alive(pid, "phase4");

    /* -- Phase 5: Dump to disk ------------------------------------- */
    write_sockets_json(&state);

    int dump_ok = dump_core(&state);
    if (dump_ok != 0)
        fprintf(stderr, "Phase 5 failed\n");
    check_alive(pid, "phase5");

    /* -- Phase 6: Kill the COW clone ------------------------------- */
    if (state.child_pid > 0) {
        kill(state.child_pid, SIGKILL);
        int ws;
        waitpid(state.child_pid, &ws, __WALL);
        printf("[phase6] COW clone (PID=%d) killed\n", (int)state.child_pid);
    }
    check_alive(pid, "phase6");

    free(state.threads.data);
    free(state.fds.data);

    return dump_ok == 0 ? 0 : 1;
}
