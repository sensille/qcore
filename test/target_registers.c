/*
 * Register-fidelity test target.
 *
 * Loads known sentinel values into three callee-saved registers (rbx, r12,
 * r13) and keeps them there while idling in short nanosleep()s.  The test
 * reads the core, extracts NT_PRSTATUS, and verifies those exact values.
 *
 * Why a nanosleep loop instead of pause():
 *   qcore's default safe mode races for a thread at a syscall-exit boundary.
 *   pause() blocks forever (no exit), so a pure-pause target would make safe
 *   mode time out.  nanosleep returns every few ms, giving safe mode a clean
 *   exit to win on -- and because rbx/r12/r13 are callee-saved and reloaded
 *   each iteration, the sentinels are present in the registers throughout the
 *   sleep, so whatever instant qcore freezes, NT_PRSTATUS captures them.
 *
 * The sentinels survive even if this thread is chosen as the parasite
 * injector: qcore restores the saved registers (captured before running the
 * parasite) and PT_NOTE is built from those saved registers.
 */
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>

#define SENTINEL_RBX  0xDEADBEEF12345678ULL
#define SENTINEL_R12  0xCAFEBABE87654321ULL
#define SENTINEL_R13  0x0FACADE1DEFACE0DULL

int main(void)
{
    printf("ready pid=%d rbx=0x%llx r12=0x%llx r13=0x%llx\n",
           getpid(),
           (unsigned long long)SENTINEL_RBX,
           (unsigned long long)SENTINEL_R12,
           (unsigned long long)SENTINEL_R13);
    fflush(stdout);

    volatile uint64_t s_rbx = SENTINEL_RBX;
    volatile uint64_t s_r12 = SENTINEL_R12;
    volatile uint64_t s_r13 = SENTINEL_R13;
    struct timespec ts = { 0, 5 * 1000 * 1000 };   /* 5 ms */

    for (;;) {
        /*
         * One asm block per iteration: reload the sentinels into the
         * callee-saved registers, then issue SYS_nanosleep (35).  The
         * sentinels stay in rbx/r12/r13 across the syscall (the kernel
         * preserves callee-saved registers), so they are present at any
         * freeze instant during the sleep.
         */
        long ret;
        __asm__ volatile (
            "movq %1, %%rbx\n\t"
            "movq %2, %%r12\n\t"
            "movq %3, %%r13\n\t"
            "movq %4, %%rdi\n\t"     /* rdi = &ts          */
            "xorl %%esi, %%esi\n\t"  /* rsi = NULL (rem)   */
            "movl $35, %%eax\n\t"    /* SYS_nanosleep      */
            "syscall"
            : "=a"(ret)
            : "m"(s_rbx), "m"(s_r12), "m"(s_r13), "r"(&ts)
            : "rbx", "r12", "r13", "rdi", "rsi", "rcx", "r11", "memory"
        );
        (void)ret;
    }
}
