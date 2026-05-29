/*
 * target_callstack - multi-threaded target with verifiable call chains.
 *
 * Each thread blocks in pause() at the bottom of a chain of uniquely named
 * __attribute__((noinline)) functions.  The test loads the core in GDB and
 * checks that every expected function name appears in the right thread's
 * backtrace, verifying that:
 *
 *   1. NT_PRSTATUS registers (RIP/RSP) are correct for every thread.
 *   2. The memory snapshot contains intact stack frames at those RSP values.
 *   3. NT_FILE correctly encodes the binary load address (symbol resolution).
 *
 * Compiled with -no-pie so GDB can resolve symbols without relying on
 * NT_FILE load-bias arithmetic (that is tested separately).
 * Compiled with -fno-omit-frame-pointer so frame-pointer unwinding works
 * even if DWARF info is unavailable.
 */
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/prctl.h>

/* ------------------------------------------------------------------ */
/* Thread 1 - three application frames deep                            */

__attribute__((noinline)) static void tc_t1_leaf(void)  { while (1) pause(); }
__attribute__((noinline)) static void tc_t1_mid(void)   { tc_t1_leaf(); }
__attribute__((noinline)) static void tc_t1_entry(void) { tc_t1_mid(); }

static void *tc_thread1(void *arg) {
    (void)arg;
    prctl(PR_SET_NAME, "tc-thread1", 0, 0, 0);
    tc_t1_entry();
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Thread 2 - two application frames deep                              */

__attribute__((noinline)) static void tc_t2_leaf(void)  { while (1) pause(); }
__attribute__((noinline)) static void tc_t2_entry(void) { tc_t2_leaf(); }

static void *tc_thread2(void *arg) {
    (void)arg;
    prctl(PR_SET_NAME, "tc-thread2", 0, 0, 0);
    tc_t2_entry();
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Thread 3 - one application frame deep                               */

__attribute__((noinline)) static void tc_t3_leaf(void) { while (1) pause(); }

static void *tc_thread3(void *arg) {
    (void)arg;
    prctl(PR_SET_NAME, "tc-thread3", 0, 0, 0);
    tc_t3_leaf();
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Main thread - two application frames deep                           */

__attribute__((noinline)) static void tc_main_leaf(void)    { while (1) pause(); }
__attribute__((noinline)) static void tc_main_blocker(void) { tc_main_leaf(); }

int main(void)
{
    pthread_t t1, t2, t3;
    pthread_create(&t1, NULL, tc_thread1, NULL);
    pthread_create(&t2, NULL, tc_thread2, NULL);
    pthread_create(&t3, NULL, tc_thread3, NULL);

    /* Let all threads reach their blocked state before we announce. */
    usleep(100000);

    printf("ready pid=%d threads=4\n", getpid());
    fflush(stdout);

    prctl(PR_SET_NAME, "tc-main", 0, 0, 0);
    tc_main_blocker();
    return 0;
}
