/*
 * target_children - verifies the double-fork leaves no child in target's tree.
 *
 * Monitors /proc/self/children continuously and reports any unexpected entry.
 * The old single-fork approach left the COW clone as a direct child of the
 * target, which triggered watchdogs in production systems (e.g. Ceph OSD).
 *
 * The double-fork + reparent-to-init design means the target should never
 * see any new children in its process tree.
 *
 * Reports "unexpected_child <pid>" to stderr if any appear; the test
 * harness checks that this message is absent.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

static volatile int stop = 0;

static void sigusr1_handler(int sig) { (void)sig; stop = 1; }

/* Returns 1 if any PID other than known_child appears in /proc/self/children. */
static int check_children(void)
{
    char buf[4096];
    int fd = open("/proc/self/children", O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';

    /* Any non-whitespace token is an unexpected child PID. */
    char *p = buf;
    while (*p) {
        while (*p == ' ' || *p == '\n') p++;
        if (*p == '\0') break;
        /* Found a PID */
        int cpid = atoi(p);
        if (cpid > 0) {
            fprintf(stderr, "unexpected_child %d\n", cpid);
            fflush(stderr);
        }
        while (*p && *p != ' ' && *p != '\n') p++;
    }
    return 0;
}

int main(void)
{
    signal(SIGUSR1, sigusr1_handler);
    printf("ready pid=%d\n", getpid());
    fflush(stdout);

    /* Poll /proc/self/children every 10ms until SIGUSR1. */
    while (!stop) {
        check_children();
        usleep(10000);
    }
    return 0;
}
