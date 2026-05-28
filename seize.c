/*
 * Phase 1 – Race-condition-safe thread seizing.
 *
 * We iterate /proc/<pid>/task in a loop, attaching any TID we haven't seen
 * yet.  We only stop iterating when a full directory scan produces zero new
 * attachments.  After the loop every thread is in ptrace-stop and we harvest
 * its GP registers for the PT_NOTE section.
 */
#include "qcore.h"

static int thread_in_set(const thread_set_t *set, pid_t tid)
{
    for (int i = 0; i < set->count; i++)
        if (set->data[i].tid == tid)
            return 1;
    return 0;
}

static thread_info_t *add_thread(thread_set_t *set, pid_t tid)
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
            pid_t tid = (pid_t)atoi(ent->d_name);
            if (tid <= 0)
                continue;
            if (thread_in_set(&state->threads, tid))
                continue;

            if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) == -1) {
                if (errno == ESRCH) {
                    /* Thread exited between readdir and attach – benign. */
                    continue;
                }
                fprintf(stderr, "PTRACE_ATTACH(%d): %s\n", (int)tid, strerror(errno));
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
            break;   /* Full scan found nothing new – all threads are seized. */
    }

    if (state->threads.count == 0) {
        fprintf(stderr, "No threads found for pid %d\n", (int)state->target_pid);
        return -1;
    }

    /*
     * Wait for every attached thread to reach ptrace-stop and harvest
     * registers.  Threads that exit between attach and waitpid are silently
     * removed from the set.
     */
    int valid = 0;
    for (int i = 0; i < state->threads.count; i++) {
        thread_info_t *t = &state->threads.data[i];
        int status = 0;

        if (waitpid(t->tid, &status, __WALL) == -1) {
            fprintf(stderr, "waitpid(%d): %s – skipping\n",
                    (int)t->tid, strerror(errno));
            t->tid = -1;   /* mark as invalid */
            continue;
        }

        if (!WIFSTOPPED(status)) {
            fprintf(stderr, "TID %d not stopped (status=0x%x) – skipping\n",
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
        valid++;
    }

    /* Compact out any TIDs marked invalid. */
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
