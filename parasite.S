/*
 * qcore parasite - x86-64 position-independent shellcode
 *
 * Entry registers set by qcore before PTRACE_CONT:
 *   %r15 = base of 3-page allocation (scratch | child1-stack | code)
 *   %r14 = fd close limit (target's RLIMIT_NOFILE soft value, capped at 1M)
 *
 * Scratch page layout (%r15 + 0):
 *   [0..7]    u64 child2_pid  written by Child 1, read by Parent spin
 *             0 = not yet written; -1 = error (clone failed / timeout)
 *   [8..4095] Child 1 stack   top = %r15 + 4096
 *
 * Code page (%r15 + 8192): this code.
 *
 * Execution paths
 * ---------------
 * PARENT (%rax > 0 after first clone):
 *   Spin on scratch[0] with a finite counter in %r13 (~10M iterations,
 *   a fraction of a second).  On timeout write -1 and int3 so qcore can
 *   detect the failure and restore cleanly.  On success load child2_pid
 *   into %rax and int3.
 *
 * CHILD 1 (%rax == 0 after first clone):
 *   Second clone (flags=0) -> Child 2.  Write the result (positive PID or
 *   negative errno) to scratch[0] and exit.  A negative value here causes
 *   qcore to abort gracefully; the parent will read it from the spin loop.
 *
 * CHILD 2 (%rax == 0 after second clone):
 *   Close fds 0 .. (r14-1) so SIGKILL does not trigger TCP RST/FIN,
 *   io_uring teardowns, or POSIX lock drops.  Then SIGSTOP and loop.
 */

	.intel_syntax noprefix
	.text
	.global parasite_start
	.global parasite_end

parasite_start:

/* ---- First clone: CLONE_VM ---------------------------------------- */
/* Child 1 shares the parent's address space so its write to scratch[0]
 * is instantly visible to the parent without IPC.
 * exit_signal byte = 0x100 & 0xff = 0 (no SIGCHLD to parent).         */

	mov	eax, 56			/* SYS_clone                           */
	mov	edi, 0x100		/* CLONE_VM; exit_signal = 0           */
	lea	rsi, [r15 + 4096]	/* child1 stack top (page 1)           */
	xor	edx, edx
	xor	r10d, r10d
	xor	r8d, r8d
	syscall

	test	rax, rax
	jg	parent_path		/* rax > 0 -> parent                   */
	js	parent_path		/* rax < 0 -> clone failed, handle in parent */

/* ---- Child 1: create COW snapshot --------------------------------- */

	mov	eax, 56			/* SYS_clone                           */
	xor	edi, edi		/* flags=0: COW + exit_signal=0        */
	xor	esi, esi		/* child_stack=0 (inherit)             */
	xor	edx, edx
	xor	r10d, r10d
	xor	r8d, r8d
	syscall

	/* rax > 0: Child 1 (parent of Child 2) -- store pid and exit.
	 * rax == 0: Child 2 -- fall through to fd scrub.
	 * rax < 0: second clone failed -- store negative errno and exit. */
	test	rax, rax
	jnz	child1_store

/* ---- Child 2: fd scrub then pause --------------------------------- */
/* Close every fd 0 .. (r14-1).  r14 was set by qcore to the target's
 * RLIMIT_NOFILE soft limit so all fds actually held by the process are
 * covered.  The kernel silently ignores EBADF.                        */

	xor	ebx, ebx
child2_close_loop:
	mov	eax, 3			/* SYS_close                           */
	mov	edi, ebx
	syscall
	inc	rbx
	cmp	rbx, r14		/* 64-bit compare against dynamic limit */
	jl	child2_close_loop

child2_sigstop_loop:
	mov	eax, 39			/* SYS_getpid                          */
	syscall
	mov	rdi, rax
	mov	esi, 19			/* SIGSTOP                             */
	mov	eax, 62			/* SYS_kill                            */
	syscall
	jmp	child2_sigstop_loop

/* ---- Child 1 cleanup ---------------------------------------------- */
child1_store:
	/* Store the result (positive child2_pid or negative errno).
	 * Visible immediately to parent via CLONE_VM shared pages.        */
	mov	QWORD PTR [r15], rax

	xor	edi, edi
	mov	eax, 60			/* SYS_exit                            */
	syscall

/* ---- Parent: spin with timeout, then int3 ------------------------- */
parent_path:
	/* Handle the case where the first clone() itself failed (rax < 0).
	 * Write the error code to scratch[0] and fall through to int3 so
	 * qcore receives rax < 0 and can abort cleanly.                   */
	test	rax, rax
	js	parent_clone_failed

	/* Load a spin counter.  ~10M iterations takes well under a second
	 * on any modern CPU.  If Child 1 doesn't write child2_pid in time
	 * (OOM-kill, kernel bug, etc.) we write -1 and trap so qcore can
	 * restore the thread rather than deadlocking the target process.  */
	mov	r13, 10000000
parent_spin:
	pause
	mov	rax, QWORD PTR [r15]
	test	rax, rax
	jnz	parent_done		/* non-zero: Child 1 wrote a result   */
	dec	r13
	jnz	parent_spin

	/* Timeout: Child 1 never wrote to scratch[0].                     */
	mov	QWORD PTR [r15], -1
	mov	rax, -1
	jmp	parent_trap

parent_clone_failed:
	/* First clone() failed; rax already holds the negative errno.     */
	mov	QWORD PTR [r15], rax

parent_done:
	/* rax = child2_pid (positive) or error sentinel (negative).       */

parent_trap:
	int3

	/* Unreachable: qcore restores rip/regs before PTRACE_DETACH.      */
	ud2

parasite_end:
