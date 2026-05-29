/*
 * target_callstack - multi-threaded target with verifiable call chains.
 *
 * Each thread idles at the bottom of a chain of uniquely named
 * __attribute__((noinline)) functions.  The test loads the core in GDB and
 * checks that every expected function name appears in the right thread's
 * backtrace, verifying that:
 *
 *   1. NT_PRSTATUS registers (RIP/RSP) are correct for every thread.
 *   2. The memory snapshot contains intact stack frames at those RSP values.
 *   3. NT_AUXV/NT_FILE let GDB place the PIE and resolve symbols.
 *
 * Built as PIE (the modern distro default) so the test exercises NT_AUXV
 * load-bias resolution exactly as real-world binaries do.
 *
 * The leaves idle in short nanosleep()s (qcore_idle_loop) rather than
 * blocking forever in pause(), so qcore's default safe mode can win its
 * race to a syscall-exit.
 */
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <time.h>

/*
 * Each leaf issues nanosleep directly via inline asm so the `syscall`
 * instruction lives inside the leaf function itself.  This guarantees the
 * leaf appears as the innermost frame (frame #0) in a backtrace -- using a
 * helper like qcore_idle_loop() would insert an extra frame even with
 * always_inline at -O0, because GCC does not honour always_inline at -O0
 * for functions with a non-trivial body.
 */
#define LEAF_IDLE_LOOP()                                        \
    do {                                                        \
        struct timespec _ts = { 0, 5 * 1000 * 1000 }; /* 5ms */ \
        for (;;) {                                              \
            long _r;                                            \
            __asm__ volatile (                                  \
                "movl $35, %%eax\n\t"  /* SYS_nanosleep */     \
                "syscall"                                       \
                : "=a"(_r)                                      \
                : "D"(&_ts), "S"(0L)                            \
                : "rcx", "r11", "memory"                        \
            );                                                  \
        }                                                       \
    } while (0)

/* ------------------------------------------------------------------ */
/* Thread 1 - three application frames deep                            */

__attribute__((noinline)) static void tc_t1_leaf(void)  { LEAF_IDLE_LOOP(); }
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

__attribute__((noinline)) static void tc_t2_leaf(void)  { LEAF_IDLE_LOOP(); }
__attribute__((noinline)) static void tc_t2_entry(void) { tc_t2_leaf(); }

static void *tc_thread2(void *arg) {
    (void)arg;
    prctl(PR_SET_NAME, "tc-thread2", 0, 0, 0);
    tc_t2_entry();
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Thread 3 - one application frame deep                               */

__attribute__((noinline)) static void tc_t3_leaf(void) { LEAF_IDLE_LOOP(); }

static void *tc_thread3(void *arg) {
    (void)arg;
    prctl(PR_SET_NAME, "tc-thread3", 0, 0, 0);
    tc_t3_leaf();
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Main thread - two application frames deep                           */

__attribute__((noinline)) static void tc_main_leaf(void)    { LEAF_IDLE_LOOP(); }
__attribute__((noinline)) static void tc_main_blocker(void) { tc_main_leaf(); }

int main(void)
{
    pthread_t t1, t2, t3;
    pthread_create(&t1, NULL, tc_thread1, NULL);
    pthread_create(&t2, NULL, tc_thread2, NULL);
    pthread_create(&t3, NULL, tc_thread3, NULL);

    /* Let all threads reach their idle state before we announce. */
    usleep(100000);

    printf("ready pid=%d threads=4\n", getpid());
    fflush(stdout);

    prctl(PR_SET_NAME, "tc-main", 0, 0, 0);
    tc_main_blocker();
    return 0;
}
