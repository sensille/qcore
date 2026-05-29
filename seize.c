/*
 * Phase 1 - Race-condition-safe thread seizing.
 *
 * Uses PTRACE_SEIZE + PTRACE_INTERRUPT instead of PTRACE_ATTACH.
 * PTRACE_ATTACH sends SIGSTOP to every thread; even though ptrace consumes
 * the signal on detach, the signal delivery machinery can disturb futex wait
 * queues, signal masks, and pending-signal state in ways that accumulate
 * across repeated invocations and eventually break the target.
 *
 * PTRACE_SEIZE attaches without sending any signal.  PTRACE_INTERRUPT stops
 * each thread via a ptrace-internal PTRACE_EVENT_STOP that is invisible to
 * the application's signal handling.
 */
#include "qcore.h"

static int thread_in_set(const thread_set_t *set, pid_t tid)
{
    for (int i = 0; i < set->count; i++)
        if (set->data[i].tid == tid)
            return 1;
    return 0;
}

thread_info_t *add_thread(thread_set_t *set, pid_t tid)
{
    if (set->count == set->capacity) {
        int nc = set->capacity ? set->capacity * 2 : DA_INIT_CAP;
        thread_info_t *p = realloc(set->data, (size_t)nc * sizeof(*p));
        if (!p) { perror("realloc thread_set"); return NULL; }
        set->data     = p;
        set->capacity = nc;
    }
    thread_info_t *t = &set->data[set->count++];
    memset(t, 0, sizeof(*t));
    t->tid = tid;
    return t;
}

int seize_all_threads(qcore_state_t *state)
{
    char task_dir[64];
    snprintf(task_dir, sizeof(task_dir), "/proc/%d/task", (int)state->target_pid);

    for (;;) {
        DIR *d = opendir(task_dir);
        if (!d) {
            fprintf(stderr, "opendir(%s): %s\n", task_dir, strerror(errno));
            return -1;
        }

        int new_count = 0;
        struct dirent *ent;

        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.')
                continue;
            pid_t tid = (pid_t)((int)strtol(ent->d_name, NULL, 10));
            if (tid <= 0)
                continue;
            if (thread_in_set(&state->threads, tid))
                continue;

            if (ptrace(PTRACE_SEIZE, tid, 0, 0) == -1) {
                if (errno == ESRCH)
                    continue;
                fprintf(stderr, "PTRACE_SEIZE(%d): %s\n", (int)tid, strerror(errno));
                closedir(d);
                return -1;
            }

            if (ptrace(PTRACE_INTERRUPT, tid, 0, 0) == -1) {
                if (errno == ESRCH)
                    continue;
                fprintf(stderr, "PTRACE_INTERRUPT(%d): %s\n", (int)tid, strerror(errno));
                closedir(d);
                return -1;
            }

            if (!add_thread(&state->threads, tid)) {
                closedir(d);
                return -1;
            }
            new_count++;
        }
        closedir(d);

        if (new_count == 0)
            break;
    }

    if (state->threads.count == 0) {
        fprintf(stderr, "No threads found for pid %d\n", (int)state->target_pid);
        return -1;
    }

    int valid = 0;
    for (int i = 0; i < state->threads.count; i++) {
        thread_info_t *t = &state->threads.data[i];
        int status = 0;

        if (waitpid(t->tid, &status, __WALL) == -1) {
            fprintf(stderr, "waitpid(%d): %s - skipping\n",
                    (int)t->tid, strerror(errno));
            t->tid = -1;
            continue;
        }

        if (!WIFSTOPPED(status)) {
            fprintf(stderr, "TID %d not stopped (status=0x%x) - skipping\n",
                    (int)t->tid, status);
            t->tid = -1;
            continue;
        }

        if (ptrace(PTRACE_GETREGS, t->tid, NULL, &t->regs) == 0) {
            t->regs_valid = 1;
        } else {
            fprintf(stderr, "PTRACE_GETREGS(%d): %s\n",
                    (int)t->tid, strerror(errno));
        }

        /* Read the thread's name and namespace-local TID from
         * /proc/<pid>/task/<tid>/status in one pass.
         *
         * NSpid lists PIDs from outermost (root/host) to innermost
         * (container) namespace.  The last value is the TID as seen
         * from inside the container; equals t->tid when not nested. */
        t->ns_tid = t->tid;   /* default: same namespace */
        {
            char status_path[64];
            snprintf(status_path, sizeof(status_path),
                     "/proc/%d/task/%d/status",
                     (int)state->target_pid, (int)t->tid);
            FILE *sf = fopen(status_path, "r");
            if (sf) {
                char line[256];
                while (fgets(line, sizeof(line), sf)) {
                    if (strncmp(line, "Name:", 5) == 0) {
                        char *p = line + 5;
                        while (*p == '\t' || *p == ' ') p++;
                        strncpy(t->name, p, sizeof(t->name) - 1);
                        t->name[sizeof(t->name) - 1] = '\0';
                        char *nl = strchr(t->name, '\n');
                        if (nl) *nl = '\0';
                    } else if (strncmp(line, "NSpid:", 6) == 0) {
                        /* Parse all whitespace-separated values; keep last. */
                        char *p = line + 6;
                        long last = t->tid;
                        while (*p) {
                            char *end;
                            long v = strtol(p, &end, 10);
                            if (end == p) break;
                            last = v;
                            p = end;
                        }
                        t->ns_tid = (pid_t)last;
                    }
                }
                fclose(sf);
            }
        }
        valid++;
    }

    int dst = 0;
    for (int i = 0; i < state->threads.count; i++) {
        if (state->threads.data[i].tid > 0)
            state->threads.data[dst++] = state->threads.data[i];
    }
    state->threads.count = dst;

    printf("[phase1] seized %d thread(s) for pid %d\n",
           valid, (int)state->target_pid);
    return 0;
}
