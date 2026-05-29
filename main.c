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

/* -- PID namespace translation ----------------------------------------- */

/*
 * The parasite runs inside the target's PID namespace and reports child2_pid
 * as seen from that namespace.  If the target is in a container, that is a
 * namespace-local PID and PTRACE_ATTACH from the host will fail with ESRCH.
 *
 * To find the host-namespace PID: compare /proc/target/ns/pid with our own;
 * if they differ, scan /proc for a process that (a) is in the same namespace
 * as the target and (b) has ns_local_pid as its innermost NSpid entry.
 * The first NSpid field is always the host (root-namespace) PID.
 */
static pid_t translate_ns_pid(pid_t target_pid, pid_t ns_local_pid)
{
    char target_ns[256] = {0};
    char self_ns[256]   = {0};
    char path[64];

    snprintf(path, sizeof(path), "/proc/%d/ns/pid", (int)target_pid);
    if (readlink(path, target_ns, sizeof(target_ns) - 1) < 0)
        return ns_local_pid;

    if (readlink("/proc/self/ns/pid", self_ns, sizeof(self_ns) - 1) < 0)
        return ns_local_pid;

    if (strcmp(target_ns, self_ns) == 0)
        return ns_local_pid;    /* same namespace: ns_local_pid is host PID */

    /*
     * Different namespaces.  Scan /proc for a process whose:
     *   - PID namespace symlink matches the target's (same container)
     *   - LAST NSpid field equals ns_local_pid (innermost namespace PID)
     * The FIRST NSpid field is the host-namespace (root) PID we need.
     */
    DIR *d = opendir("/proc");
    if (!d) return ns_local_pid;

    pid_t found = -1;
    struct dirent *ent;

    while ((ent = readdir(d)) != NULL && found < 0) {
        if (ent->d_name[0] < '1' || ent->d_name[0] > '9') continue;
        int hpid = (int)strtol(ent->d_name, NULL, 10);
        if (hpid <= 0) continue;

        /* Must be in the same PID namespace as the target. */
        char proc_ns[256] = {0};
        snprintf(path, sizeof(path), "/proc/%d/ns/pid", hpid);
        if (readlink(path, proc_ns, sizeof(proc_ns) - 1) < 0) continue;
        if (strcmp(proc_ns, target_ns) != 0) continue;

        /* Parse NSpid: last field = innermost PID, first = host PID. */
        char status[128];
        snprintf(status, sizeof(status), "/proc/%d/status", hpid);
        FILE *f = fopen(status, "r");
        if (!f) continue;

        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "NSpid:", 6) != 0) continue;
            char *p = line + 6;
            long first = -1, last = -1;
            while (*p) {
                char *end;
                long v = strtol(p, &end, 10);
                if (end == p) break;
                if (first < 0) first = v;
                last = v;
                p = end;
            }
            if (last == (long)ns_local_pid && first > 0)
                found = (pid_t)first;
            break;
        }
        fclose(f);
    }
    closedir(d);

    if (found > 0) {
        printf("[phase5] namespace PID %d -> host PID %d\n",
               (int)ns_local_pid, (int)found);
        return found;
    }

    fprintf(stderr, "[phase5] warning: could not map ns-PID %d to host PID\n",
            (int)ns_local_pid);
    return ns_local_pid;   /* fallback: try as-is */
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
    double t_seize = qcore_now_ms();
    if (seize_all_threads(&state) != 0) {
        fprintf(stderr, "Phase 1 failed\n");
        return 1;
    }
    double t_seized = qcore_now_ms();
    printf("[timing]  seize %d thread(s): %.2f ms  <-- target frozen here\n",
           state.threads.count, t_seized - t_seize);
    check_alive(pid, "phase1");

    /* Phase 2 (FD harvest, concurrent with frozen state) ------------ */
    double t_fds = qcore_now_ms();
    harvest_fds(&state);
    printf("[timing]  fd harvest:         %.2f ms\n", qcore_now_ms() - t_fds);
    check_alive(pid, "phase2");

    /* Phases 2-4: inject parasite, run, detach ---------------------- */
    double t_inject = qcore_now_ms();
    if (inject_parasite(&state) != 0) {
        fprintf(stderr, "Parasite injection failed - emergency detach\n");
        for (int i = 0; i < state.threads.count; i++)
            ptrace(PTRACE_DETACH, state.threads.data[i].tid, NULL, NULL);
        return 1;
    }
    double t_resumed = qcore_now_ms();
    printf("[timing]  inject+detach:      %.2f ms\n", t_resumed - t_inject);
    printf("[timing]  TARGET FROZEN FOR:  %.2f ms  <-- target running again\n",
           t_resumed - t_seized);
    check_alive(pid, "phase4");

    /* Phase 5: attach child2, build ELF ----------------------------- */
    /* Translate the namespace-local PID the parasite reported to the
     * host-namespace PID that PTRACE_ATTACH requires.  This is a no-op
     * when qcore and the target are in the same PID namespace. */
    state.child2_pid = translate_ns_pid(state.target_pid, state.child2_pid);

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
