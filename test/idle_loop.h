/*
 * Shared idle loop for qcore test targets.
 *
 * Real processes are not parked forever in a single blocking syscall -- they
 * wake periodically (timers, polls, work).  qcore's default "safe mode" races
 * for a thread at a clean syscall boundary, so test targets must model that
 * periodic activity rather than blocking eternally in pause().
 *
 * qcore_idle_loop() spins in short nanosleep()s: the thread is in a syscall
 * almost all the time (so it is a realistic blocked thread), but completes a
 * syscall every few ms, giving safe mode a syscall-exit to win on quickly.
 *
 * Use -f / QCORE_RACE_TIMEOUT for targets that intentionally block forever.
 */
#ifndef QCORE_IDLE_LOOP_H
#define QCORE_IDLE_LOOP_H

#include <time.h>

/*
 * Idle by issuing SYS_nanosleep DIRECTLY via inline asm (always_inline), so
 * the `syscall` instruction lands in the *calling* function.  When the thread
 * is blocked, its innermost user-space frame is the caller itself -- not a
 * libc nanosleep/clock_nanosleep wrapper.  This keeps backtraces clean: the
 * caller (e.g. a leaf function) appears as frame #0 rather than being hidden
 * behind libc frames the unwinder may not traverse.
 */
__attribute__((always_inline))
static inline void qcore_idle_loop(void)
{
    struct timespec ts = { 0, 5 * 1000 * 1000 };  /* 5 ms */
    for (;;) {
        long ret;
        __asm__ volatile (
            "movl $35, %%eax\n\t"        /* SYS_nanosleep */
            "syscall"
            : "=a"(ret)
            : "D"(&ts), "S"(0L)          /* rdi=&ts, rsi=NULL (rem) */
            : "rcx", "r11", "memory"
        );
        (void)ret;
    }
}

#endif /* QCORE_IDLE_LOOP_H */
