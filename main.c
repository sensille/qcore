/*
 * qcore – Instant Core GDB Loader
 *
 * Usage: qcore <pid>
 *
 * Produces:
 *   core.<pid>          – ELF64 core file loadable by gdb/lldb
 *   core.<pid>.sockets.json – socket/FD inventory of the target
 *
 * Must be run as root or with CAP_SYS_PTRACE.
 */
#include "qcore.h"

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <pid>\n", prog);
}

int main(int argc, char *argv[])
{
    if (argc != 2) { usage(argv[0]); return 1; }

    pid_t pid = (pid_t)atoi(argv[1]);
    if (pid <= 0) {
        fprintf(stderr, "Invalid PID: %s\n", argv[1]);
        return 1;
    }

    /* Verify the target exists before we begin. */
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

    printf("qcore: targeting PID %d\n", (int)pid);
    printf("  output core:    %s\n", state.core_path);
    printf("  output sockets: %s\n", state.sockets_json_path);

    /* ── Phase 1: Seize all threads ─────────────────────────────── */
    if (seize_all_threads(&state) != 0) {
        fprintf(stderr, "Phase 1 failed\n");
        return 1;
    }

    /* ── Phase 2: Harvest FD / socket info ──────────────────────── */
    if (harvest_fds(&state) != 0) {
        fprintf(stderr, "Phase 2 failed\n");
        /* Non-fatal: continue without socket info */
    }

    /* ── Phase 3: COW clone via injected fork() ─────────────────── */
    if (cow_clone(&state) != 0) {
        fprintf(stderr, "Phase 3 failed – detaching and exiting\n");
        /* Emergency detach to unfreeze target */
        for (int i = 0; i < state.threads.count; i++)
            ptrace(PTRACE_DETACH, state.threads.data[i].tid, NULL, NULL);
        return 1;
    }

    /* ── Phase 4: Resume parent ──────────────────────────────────── */
    if (resume_parent(&state) != 0) {
        fprintf(stderr, "Phase 4 failed\n");
        /* Try to kill child to avoid a zombie COW clone */
        if (state.child_pid > 0) kill(state.child_pid, SIGKILL);
        return 1;
    }

    /* ── Phase 5: Dump to disk ───────────────────────────────────── */
    write_sockets_json(&state);   /* write JSON first (already collected) */

    int dump_ok = dump_core(&state);
    if (dump_ok != 0)
        fprintf(stderr, "Phase 5 failed\n");

    /* ── Phase 6: Kill the COW clone ─────────────────────────────── */
    if (state.child_pid > 0) {
        kill(state.child_pid, SIGKILL);
        /* Reap the child to avoid zombies */
        int ws;
        waitpid(state.child_pid, &ws, __WALL);
        printf("[phase6] COW clone (PID=%d) killed\n", (int)state.child_pid);
    }

    /* Free resources */
    free(state.threads.data);
    free(state.fds.data);

    return dump_ok == 0 ? 0 : 1;
}
