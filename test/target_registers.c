/*
 * Register-fidelity test target.
 *
 * Loads known sentinel values into three callee-saved registers (rbx, r12,
 * r13) immediately before blocking in the pause() syscall.  The test suite
 * reads the core, extracts NT_PRSTATUS, and verifies those exact values.
 *
 * Sequence:
 *   1. Print "ready" so the test harness knows the PID.
 *   2. Load sentinels + issue pause syscall in a single asm block so the
 *      compiler cannot insert spill/reload code between them.
 *   3. When woken by qcore detaching, fall through to return.
 *
 * Callee-saved registers (rbx, r12, r13) are chosen because the x86-64
 * syscall ABI does not modify them; the kernel saves them to pt_regs on
 * syscall entry so they are visible via PTRACE_GETREGS.
 */
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#define SENTINEL_RBX  0xDEADBEEF12345678ULL
#define SENTINEL_R12  0xCAFEBABE87654321ULL
#define SENTINEL_R13  0x0FACADE1DEFACE0DULL

int main(void)
{
    /* Announce readiness before blocking - the test harness reads this. */
    printf("ready pid=%d rbx=0x%llx r12=0x%llx r13=0x%llx\n",
           getpid(),
           (unsigned long long)SENTINEL_RBX,
           (unsigned long long)SENTINEL_R12,
           (unsigned long long)SENTINEL_R13);
    fflush(stdout);

    /*
     * Volatile intermediates so the compiler materialises actual loads into
     * the registers rather than folding the constants away.
     */
    volatile uint64_t s_rbx = SENTINEL_RBX;
    volatile uint64_t s_r12 = SENTINEL_R12;
    volatile uint64_t s_r13 = SENTINEL_R13;

    /*
     * Single asm block: load sentinels then issue SYS_pause (34).
     * No compiler-generated code can appear between the movq's and the
     * syscall because they are in the same asm statement.
     */
    __asm__ volatile (
        "movq %0, %%rbx\n\t"
        "movq %1, %%r12\n\t"
        "movq %2, %%r13\n\t"
        "movl $34, %%eax\n\t"   /* SYS_pause */
        "syscall"
        :
        : "m"(s_rbx), "m"(s_r12), "m"(s_r13)
        : "rax", "rbx", "r12", "r13", "rcx", "r11", "memory"
    );

    /* qcore has detached; keep the process alive so the liveness test passes */
    while (1) pause();
}
