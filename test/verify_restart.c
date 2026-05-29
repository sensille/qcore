/*
 * verify_restart.c - empirically test the "transparent restart" assumption.
 *
 * qcore's safety model rests on this claim:
 *
 *   Seizing a syscall-blocked thread with PTRACE_SEIZE + PTRACE_INTERRUPT,
 *   then PTRACE_DETACH-ing it WITHOUT delivering a signal or modifying
 *   registers, lets the kernel transparently RESTART the interrupted
 *   syscall -- the application never observes -EINTR.
 *
 * This is known-true for ERESTARTSYS / ERESTARTNOINTR syscalls.  The open
 * question is ERESTARTNOHAND syscalls (epoll_wait, poll, select), which
 * normally return -EINTR when an actual signal handler runs.  Does a bare
 * ptrace stop (no signal) also force -EINTR, or does it restart?
 *
 * This program answers it directly:
 *   - fork() a child that loops blocking in a chosen syscall and counts
 *     every time the syscall returns -EINTR.
 *   - The parent repeats qcore's exact freeze cycle N times.
 *   - If the child's EINTR count is 0 after N cycles, the syscall restarts
 *     transparently and qcore's freeze is safe for that syscall type.
 *
 * ptrace_scope=1 permits tracing a direct child, so no root/sudo needed.
 *
 * Build:  gcc -O0 -g -o verify_restart verify_restart.c
 * Run:    ./verify_restart
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <poll.h>
#include <time.h>

#define N_CYCLES 200

/* Shared counters between parent and child (MAP_SHARED anonymous). */
struct shared {
    volatile long eintr;        /* times the syscall returned -EINTR     */
    volatile long completed;    /* times it returned normally (>=0)      */
    volatile long iterations;   /* total loop iterations (progress)      */
    volatile int  ready;        /* child has entered its loop            */
};

static struct shared *sh;

/* ------------------------------------------------------------------ */
/* Child workloads: each blocks in one syscall type forever and counts */
/* EINTR returns.                                                       */

static void child_epoll(void)   /* ERESTARTNOHAND */
{
    int efd = epoll_create1(0);
    int evfd = eventfd(0, 0);    /* never signaled */
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = evfd };
    epoll_ctl(efd, EPOLL_CTL_ADD, evfd, &ev);

    sh->ready = 1;
    for (;;) {
        struct epoll_event out[1];
        int n = epoll_wait(efd, out, 1, -1);
        sh->iterations++;
        if (n < 0 && errno == EINTR) sh->eintr++;
        else                         sh->completed++;
    }
}

static void child_poll(void)    /* ERESTARTNOHAND */
{
    int evfd = eventfd(0, 0);
    sh->ready = 1;
    for (;;) {
        struct pollfd pfd = { .fd = evfd, .events = POLLIN };
        int n = poll(&pfd, 1, -1);
        sh->iterations++;
        if (n < 0 && errno == EINTR) sh->eintr++;
        else                         sh->completed++;
    }
}

static void child_read_pipe(void)  /* ERESTARTSYS - control case */
{
    int pp[2];
    if (pipe(pp) != 0) _exit(2);
    sh->ready = 1;
    for (;;) {
        char buf[1];
        ssize_t n = read(pp[0], buf, 1);   /* blocks: nothing written */
        sh->iterations++;
        if (n < 0 && errno == EINTR) sh->eintr++;
        else                         sh->completed++;
    }
}

/* ------------------------------------------------------------------ */
/* The freezer: qcore's exact seize -> interrupt -> detach cycle.       */

static int run_case(const char *name, void (*workload)(void),
                    unsigned long expect_syscall_nr)
{
    memset(sh, 0, sizeof(*sh));

    pid_t child = fork();
    if (child < 0) { perror("fork"); return -1; }
    if (child == 0) {
        workload();          /* never returns */
        _exit(0);
    }

    /* Wait for the child to enter its loop. */
    while (!sh->ready) usleep(1000);
    usleep(10000);           /* ensure it is blocked in the syscall */

    long restart_code_seen = 0;
    int  syscall_nr_ok = 1;
    long long sample_rax = 0x7fffffff;   /* rax observed at the stop */
    unsigned long sample_orig = 0;

    for (int i = 0; i < N_CYCLES; i++) {
        /* --- exactly what qcore does --- */
        if (ptrace(PTRACE_SEIZE, child, 0, 0) == -1) {
            perror("PTRACE_SEIZE"); kill(child, SIGKILL); return -1;
        }
        if (ptrace(PTRACE_INTERRUPT, child, 0, 0) == -1) {
            perror("PTRACE_INTERRUPT"); kill(child, SIGKILL); return -1;
        }
        int st;
        if (waitpid(child, &st, 0) == -1) {
            perror("waitpid"); kill(child, SIGKILL); return -1;
        }
        if (!WIFSTOPPED(st)) {
            fprintf(stderr, "child not stopped (0x%x)\n", st);
            kill(child, SIGKILL); return -1;
        }

        /* Observe the saved registers: rax should hold a restart code
         * (-512..-516), orig_rax the syscall number. */
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == 0) {
            long long rax = (long long)regs.rax;
            if (rax <= -512 && rax >= -516) restart_code_seen++;
            if (i == 0) { sample_rax = rax; sample_orig = regs.orig_rax; }
            if (expect_syscall_nr != (unsigned long)-1 &&
                regs.orig_rax != expect_syscall_nr)
                syscall_nr_ok = 0;
        }

        /* Detach with no signal, no register change -- the critical step. */
        if (ptrace(PTRACE_DETACH, child, 0, 0) == -1) {
            perror("PTRACE_DETACH"); kill(child, SIGKILL); return -1;
        }

        /* Brief gap so the child settles back into the syscall. */
        usleep(2000);
    }

    long eintr     = sh->eintr;
    long completed = sh->completed;

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);

    /* Decode the sample rax for clarity. */
    const char *rax_name = "?";
    switch (sample_rax) {
    case -4:   rax_name = "-EINTR";          break;
    case -512: rax_name = "-ERESTARTSYS";    break;
    case -513: rax_name = "-ERESTARTNOINTR"; break;
    case -514: rax_name = "-ERESTARTNOHAND"; break;
    case -516: rax_name = "-ERESTART_RESTARTBLOCK"; break;
    default:   if (sample_rax >= 0) rax_name = "(return value)"; break;
    }

    printf("  %-12s : %d cycles | EINTR=%ld completed=%ld iters=%ld | "
           "stop rax=%lld %s orig_rax=%lu%s\n",
           name, N_CYCLES, eintr, completed, sh->iterations,
           sample_rax, rax_name, sample_orig,
           syscall_nr_ok ? "" : " [nr differs]");

    if (eintr == 0) {
        printf("  %-12s : TRANSPARENT  (no EINTR ever reached the app)\n",
               name);
        return 0;
    } else {
        printf("  %-12s : NOT TRANSPARENT  (app saw %ld EINTR)\n",
               name, eintr);
        return 1;
    }
}

int main(void)
{
    sh = mmap(NULL, sizeof(*sh), PROT_READ | PROT_WRITE,
              MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (sh == MAP_FAILED) { perror("mmap"); return 2; }

    printf("Verifying transparent-restart assumption (%d cycles each)\n",
           N_CYCLES);
    printf("ptrace_scope=%s\n",
           access("/proc/sys/kernel/yama/ptrace_scope", R_OK) == 0
               ? "(see /proc/sys/kernel/yama/ptrace_scope)" : "n/a");
    printf("\n");

    int bad = 0;
    /* __NR_epoll_wait=232, __NR_poll=7, __NR_read=0 on x86-64. */
    bad |= run_case("epoll_wait", child_epoll,     232);
    bad |= run_case("poll",       child_poll,        7);
    bad |= run_case("read(pipe)", child_read_pipe,   0);

    printf("\n");
    if (bad) {
        printf("RESULT: at least one syscall type returned -EINTR on a bare\n");
        printf("        ptrace freeze.  qcore's freeze is NOT transparent for\n");
        printf("        that type; 'safe mode' cannot be fully safe.\n");
    } else {
        printf("RESULT: all syscall types restarted transparently.  qcore's\n");
        printf("        seize->interrupt->detach freeze is side-effect free\n");
        printf("        for non-injector threads.  Safe-mode assumption holds.\n");
    }
    return bad;
}
