/*
 * qcore parasite - x86-64 position-independent shellcode
 *
 * Entry registers set by qcore before PTRACE_CONT:
 *   %r14 = fd close limit (target's RLIMIT_NOFILE soft value, capped at 1M)
 *   %r15 = base of the parasite mmap allocation (also holds this shellcode;
 *          otherwise unused by this single-fork version)
 *
 * Operation
 * ---------
 * A single clone() executed by the injector thread creates the child -- a
 * copy-on-write snapshot of the target's address space.  Because the injector
 * itself issues the clone, the child's PID is returned directly in %rax, which
 * qcore reads when the injector traps on int3.  No double-fork and no
 * shared-memory writeback are needed.
 *
 * the child is a direct child of the target with exit_signal = 0: killing it
 * sends no SIGCHLD to the target, and qcore reaps it explicitly in its final
 * cleanup phase by injecting wait4() into the target (only the target, as
 * the child's parent, can release the zombie).
 *
 * Execution paths
 * ---------------
 *   Parent (injector, %rax != 0): trap on int3.  %rax holds the child's PID
 *     in the target's PID namespace (positive) or a negative errno.
 *   the child (%rax == 0): close fds 0..r14-1 (so the eventual SIGKILL causes
 *     no TCP RST/FIN, io_uring teardown, or POSIX lock drops), then loop on
 *     kill(self, SIGSTOP) waiting for qcore to snapshot it.
 */

	.intel_syntax noprefix
	.text
	.global parasite_start
	.global parasite_end

parasite_start:

/* ---- Single clone: COW snapshot (the child) ------------------------- */
	mov	eax, 56			/* SYS_clone                           */
	xor	edi, edi		/* flags=0: COW copy, exit_signal=0    */
	xor	esi, esi		/* child_stack=0 -> COW of parent stack */
	xor	edx, edx
	xor	r10d, r10d
	xor	r8d, r8d
	syscall

	test	rax, rax
	jz	child_entry		/* rax == 0: we are the child            */
	/* parent: rax = child pid (>0) or -errno (<0); report via int3.   */

parent_trap:
	int3
	/* Unreachable: qcore restores rip/regs before PTRACE_DETACH.       */
	ud2

/* ---- the child: scrub fds, then stop ------------------------------- */
child_entry:
	/* Close every fd 0 .. (r14-1).  r14 is the target's RLIMIT_NOFILE
	 * soft limit.  The kernel silently ignores EBADF.                  */
	xor	ebx, ebx
child_close_loop:
	mov	eax, 3			/* SYS_close                           */
	mov	edi, ebx
	syscall
	inc	rbx
	cmp	rbx, r14
	jl	child_close_loop

	/* Stop and wait for qcore to read /proc/self/mem.  Loop in case we
	 * are spuriously continued. */
child_stop_loop:
	mov	eax, 39			/* SYS_getpid                          */
	syscall
	mov	rdi, rax
	mov	esi, 19			/* SIGSTOP                             */
	mov	eax, 62			/* SYS_kill                            */
	syscall
	jmp	child_stop_loop

parasite_end:
