/*
 * qcore - zero-pause core dumper for Linux x86-64
 *
 * Usage: qcore <pid>
 *
 * Produces:
 *   core.<pid>               ELF64 core loadable by gdb/lldb
 *   core.<pid>.fds.json  FD inventory
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

    int sidx = s->safe_thread_idx;

    /* Phase 3 guard: the parasite is running natively via PTRACE_CONT.
     *
     * Detectable state: mmap_addr != 0 (pages allocated) and
     * safe_bytes_modified == 0 (no injection in progress -- the bytes at
     * original RIP were already restored after mmap, before PTRACE_CONT).
     *
     * Without this guard, the injector resumes into the parasite spin-loop
     * after detach, eventually executes int3 (or ud2 on timeout), and --
     * because qcore is no longer the tracer -- the resulting SIGTRAP kills
     * the target process with its default action.
     *
     * Fix: PTRACE_INTERRUPT the injector, wait for it to stop, then
     * overwrite its registers with the original pre-injection values so it
     * resumes at its original code after PTRACE_DETACH.  The 3 mmap'd pages
     * (12KB) are left mapped -- an acceptable leak in an emergency path. */
    if (sidx >= 0 && s->mmap_addr && !s->safe_bytes_modified) {
        pid_t safe_tid = s->threads.data[sidx].tid;
        ptrace(PTRACE_INTERRUPT, safe_tid, 0, 0);
        int st;
        waitpid(safe_tid, &st, __WALL);
        ptrace(PTRACE_SETREGS, safe_tid, NULL,
               (struct user_regs_struct *)&s->safe_saved_regs);
        s->mmap_addr = 0;
    }

    /* If we modified bytes at the safe thread's RIP (mmap/munmap injection
     * in progress), restore them and the original registers. */
    if (s->safe_bytes_modified && sidx >= 0) {
        pid_t safe_tid = s->threads.data[sidx].tid;
        ptrace(PTRACE_POKETEXT, safe_tid,
               (void *)s->safe_saved_regs.rip,
               (void *)(unsigned long)s->safe_saved_word);
        ptrace(PTRACE_SETREGS, safe_tid, NULL,
               (struct user_regs_struct *)&s->safe_saved_regs);
    }

    /* Detach all parent threads.  PTRACE_DETACH works on both stopped and
     * running tracees (race mode): for running threads the kernel removes
     * the ptrace relationship and the task continues without us. */
    for (int i = 0; i < s->threads.count; i++) {
        pid_t tid = s->threads.data[i].tid;
        if (tid > 0) ptrace(PTRACE_DETACH, tid, NULL, NULL);
    }

    /* Kill child2 if it was already created. */
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

static void print_theory(void)
{
    puts(
"qcore - zero-pause core dumper for Linux x86-64\n"
"\n"
"GOAL\n"
"  Produce a complete ELF core dump of a running process while keeping the\n"
"  process frozen for the minimum possible time.  gcore freezes the process\n"
"  for the entire duration of disk I/O -- tens of seconds for a multi-GB\n"
"  process.  qcore freezes it only for a short snapshot operation (typically\n"
"  under 5 ms), then resumes the process immediately.  All disk I/O happens\n"
"  afterward against an isolated memory snapshot.\n"
"\n"
"PHASE 1 - SEIZE ALL THREADS  [target is frozen]\n"
"  qcore attaches to every thread in the process using PTRACE_SEIZE followed\n"
"  by PTRACE_INTERRUPT.  PTRACE_SEIZE attaches without sending any signal;\n"
"  PTRACE_INTERRUPT stops each thread via an internal kernel mechanism that\n"
"  is invisible to the application's signal handling.\n"
"\n"
"  The attachment loop is race-condition-safe: qcore re-reads\n"
"  /proc/<pid>/task/ after each round and keeps attaching until a full scan\n"
"  finds no new threads.  Once all threads are stopped, their GP registers\n"
"  are read with PTRACE_GETREGS and saved; these will become the NT_PRSTATUS\n"
"  notes in the final core file.\n"
"\n"
"  FD and socket information is also collected at this point from\n"
"  /proc/<pid>/fd/, /proc/<pid>/net/tcp[6], /proc/<pid>/net/udp[6], and\n"
"  /proc/<pid>/net/unix.\n"
"\n"
"PHASE 2 - FIND A CLEAN INJECTION THREAD  [target is frozen]\n"
"  The memory snapshot is created by running a small shellcode payload\n"
"  (the 'parasite') inside the target process.  To do this, qcore must\n"
"  borrow one thread (the 'injector') and temporarily redirect its\n"
"  execution.  The safest injector is one that was executing user-space code\n"
"  (not blocked in a system call) when it was stopped, because restoring its\n"
"  original registers afterward is a perfect no-op.\n"
"\n"
"  Safe mode (default):\n"
"    If no thread is in user-space, qcore releases all threads back to the\n"
"    scheduler under PTRACE_SYSCALL tracing.  The process runs normally.\n"
"    qcore waits for any thread to reach the exit of a system call -- a\n"
"    point where the call has fully completed and restoring registers leaves\n"
"    no visible effect.  The moment one thread reaches such an exit, qcore\n"
"    freezes all threads again and uses that thread as the injector.  If\n"
"    the timeout expires before any thread reaches a clean exit (a fully\n"
"    idle process where every thread is parked indefinitely), qcore refuses\n"
"    and suggests -f.\n"
"\n"
"  Force mode (-f):\n"
"    Injects into any thread regardless of its current state.  A thread\n"
"    blocked in a system call will see that call return -EINTR on resume,\n"
"    exactly as if a signal had arrived.  Correct applications handle this.\n"
"\n"
"PHASE 3 - PARASITE INJECTION AND DOUBLE-FORK  [target is frozen]\n"
"  qcore injects a mmap system call into the injector thread to allocate\n"
"  three pages of read/write/execute memory within the target's address\n"
"  space.  These pages hold a scratch area, a private stack for an\n"
"  intermediate process, and the parasite shellcode.\n"
"\n"
"  The shellcode is written to the code page and the injector is released\n"
"  with PTRACE_CONT to run it natively at full CPU speed.\n"
"\n"
"  The shellcode performs a double-fork:\n"
"\n"
"  Step A - First clone (CLONE_VM):\n"
"    Creates Child 1, which shares the parent's address space.  Any write\n"
"    by Child 1 is immediately visible to the parent without IPC.\n"
"\n"
"  Step B - Second clone (flags=0, from Child 1):\n"
"    Creates Child 2.  Because the second clone does not share address\n"
"    space, Child 2 receives a full copy-on-write snapshot of the target's\n"
"    memory at this exact moment.  This snapshot is the basis of the core.\n"
"\n"
"  Step C - Child 2:\n"
"    Closes all file descriptors from 0 to the process's open-file limit.\n"
"    This ensures that when Child 2 is eventually killed, no file\n"
"    descriptors are released, so no TCP RST/FIN packets are sent, no\n"
"    io_uring rings are torn down, and no advisory file locks are dropped.\n"
"    Child 2 then stops itself with SIGSTOP and waits.\n"
"\n"
"  Step D - Child 1:\n"
"    Writes Child 2's PID to the shared scratch page (visible immediately\n"
"    to the parent via CLONE_VM) and exits.\n"
"\n"
"  Step E - Parent (the injector):\n"
"    Spins on the scratch page until Child 2's PID appears, then signals\n"
"    qcore by executing an int3 instruction.  qcore catches the resulting\n"
"    SIGTRAP and reads Child 2's PID from the %rax register.\n"
"\n"
"  Stealth: Child 1 exits before the parent returns from the first fork.\n"
"  The OS therefore reparents Child 2 to init.  The target process never\n"
"  has Child 2 as a direct child, so process-tree monitors and watchdogs\n"
"  do not observe it.  No SIGCHLD is sent (exit_signal == 0).\n"
"\n"
"PHASE 4 - RESUME THE TARGET  [freeze ends]\n"
"  qcore injects a munmap system call to free the three parasite pages.\n"
"  The injector's original registers are restored precisely; the kernel's\n"
"  PTRACE_DETACH path with signal number 0 transparently restarts any\n"
"  interrupted system call.  All threads are detached.  The target process\n"
"  is now fully running again.  Total freeze time is typically under 5 ms.\n"
"\n"
"PHASE 5 - BUILD THE CORE FILE  [target is running]\n"
"  qcore attaches to Child 2 (which is stopped on SIGSTOP) and reads its\n"
"  memory map from /proc/child2/maps.  It streams the contents of each\n"
"  readable mapping from /proc/child2/mem into a valid ELF64 core file.\n"
"\n"
"  The ELF notes use the registers saved in Phase 1 from the *parent*,\n"
"  not Child 2's registers.  This ensures the core reflects the state of\n"
"  every thread at the moment of the freeze, not the artificial state of\n"
"  the snapshot process.\n"
"\n"
"  ELF notes written:\n"
"    NT_PRSTATUS  one per thread, Phase-1 registers (RIP, RSP, etc.)\n"
"    NT_PRPSINFO  process name and command line\n"
"    NT_AUXV      auxiliary vector -- required for GDB to determine the\n"
"                 load address of position-independent executables;\n"
"                 without it all backtrace frames appear as '?? ()'\n"
"    NT_FILE      file-backed mapping table for shared-library resolution\n"
"\n"
"  Sidecar JSON files:\n"
"    core.<pid>.fds.json     open file descriptors with type, flags,\n"
"                            socket addresses and queue depths, file\n"
"                            position and size\n"
"    core.<pid>.threads.json thread names and, for containerised targets,\n"
"                            the namespace-local TID alongside the host TID\n"
"\n"
"  With -c the ELF stream is piped through 'xz -0' and written as\n"
"  core.<pid>.xz without creating any intermediate temporary file.\n"
"\n"
"PHASE 6 - CLEANUP\n"
"  Child 2 receives SIGKILL.  Because all its file descriptors were closed\n"
"  in Phase 3, the kill has no observable side effects.  Child 2 is an\n"
"  init orphan, so the target never receives SIGCHLD for it.\n"
    );
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [-f] [-c] [-t] <pid>\n"
        "  -f   force: inject into any thread even if all are mid-syscall.\n"
        "       Default (safe) mode waits for a thread to reach a clean\n"
        "       point and refuses rather than risk disturbing the target.\n"
        "  -c   compress: write core through xz (produces core.<pid>.xz).\n"
        "       Requires xz in PATH.  Uses xz level 0 for speed.\n"
        "  -t   theory: print detailed theory of operation and exit.\n",
        prog);
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
    int force = 0, compress = 0;
    int opt;
    while ((opt = getopt(argc, argv, "fct")) != -1) {
        switch (opt) {
        case 'f': force    = 1; break;
        case 'c': compress = 1; break;
        case 't': print_theory(); return 0;
        default:  usage(argv[0]); return 1;
        }
    }
    if (optind != argc - 1) { usage(argv[0]); return 1; }

    pid_t pid = (pid_t)((int)strtol(argv[optind], NULL, 10));
    if (pid <= 0) {
        fprintf(stderr, "Invalid PID: %s\n", argv[optind]);
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
    state.force            = force;
    state.compress         = compress;
    snprintf(state.core_path, sizeof(state.core_path),
             compress ? "core.%d.xz" : "core.%d", (int)pid);
    snprintf(state.fds_json_path, sizeof(state.fds_json_path),
             "core.%d.fds.json", (int)pid);
    snprintf(state.threads_json_path, sizeof(state.threads_json_path),
             "core.%d.threads.json", (int)pid);

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
    printf("  fds:%s\n", state.fds_json_path);
    printf("  threads: %s\n", state.threads_json_path);

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

    write_fds_json(&state);
    write_threads_json(&state);

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
