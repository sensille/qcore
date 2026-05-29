/*
 * target_idle - pathological "fully idle" target.
 *
 * Every thread blocks forever in pause() with no activity, so no thread
 * ever reaches a syscall-exit.  This is the one case qcore's safe mode
 * cannot handle: it must time out and refuse, advising -f.  With -f, qcore
 * hijacks the blocked thread anyway and the dump succeeds.
 *
 * Used to test both the safe-mode refusal path and that -f works on it.
 */
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    printf("ready pid=%d\n", getpid());
    fflush(stdout);

    while (1) pause();   /* blocks forever: no syscall-exit, ever */
    return 0;
}
