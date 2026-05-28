/*
 * target_epoll - test target that blocks in epoll_wait.
 *
 * Verifies the ERESTARTNOHAND fix: a thread in epoll_wait must resume
 * transparently after qcore runs (the old cow-injection approach caused
 * this thread to receive -EINTR, which in some code paths was fatal).
 *
 * The process counts EINTR events it receives and reports them when it
 * exits so the test harness can assert 0 unexpected interruptions.
 */
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

static volatile int eintr_count = 0;

static void sigusr1_handler(int sig)
{
    (void)sig;
    /* Test harness sends SIGUSR1 to ask us to print stats. */
    printf("eintr_count=%d\n", eintr_count);
    fflush(stdout);
}

int main(void)
{
    /* Create an epoll fd and an eventfd to watch. */
    int efd = epoll_create1(0);
    if (efd < 0) { perror("epoll_create1"); return 1; }

    int evfd = eventfd(0, 0);
    if (evfd < 0) { perror("eventfd"); return 1; }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = evfd;
    epoll_ctl(efd, EPOLL_CTL_ADD, evfd, &ev);

    signal(SIGUSR1, sigusr1_handler);

    printf("ready pid=%d efd=%d\n", getpid(), efd);
    fflush(stdout);

    /* Block in epoll_wait.  If we receive -EINTR unexpectedly we count it
     * and re-enter; a correctly implemented qcore should not cause this. */
    while (1) {
        struct epoll_event events[4];
        int n = epoll_wait(efd, events, 4, -1);
        if (n < 0) {
            if (errno == EINTR) {
                eintr_count++;
                continue;
            }
            perror("epoll_wait");
            break;
        }
        /* Normal wakeup: drain the eventfd and loop. */
        uint64_t val;
        read(evfd, &val, sizeof(val));
    }
    return 0;
}
