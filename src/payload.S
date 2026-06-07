/*
 * qcore payload - x86-64 position-independent
 *
 * Entry registers set by qcore before PTRACE_CONT:
 *   %r15 = fd close limit (target's RLIMIT_NOFILE soft value)
 *
 * attention, don't call stateful syscalls here, because that could mess up the
 * restart state of the target and inject a spurious EINTR
 */

	.intel_syntax noprefix
	.text
	.global parasite_start
	.global parasite_end

parasite_start:

	mov	eax, 56			/* SYS_clone                            */
	xor	edi, edi		/* flags=0: COW copy, exit_signal=0     */
	xor	esi, esi		/* child_stack=0 -> COW of parent stack */
	xor	edx, edx
	xor	r10d, r10d
	xor	r8d, r8d
	syscall

	test	rax, rax
	jz	child_entry		/* rax == 0: we are the child           */
	int3
	//ud2

child_entry:
	/* Close every fd 0 .. (r15-1).  r15 is the target's RLIMIT_NOFILE
	 * soft limit.  The kernel silently ignores EBADF.                      */
	xor	ebx, ebx
child_close_loop:
	mov	eax, 3			/* SYS_close                            */
	mov	edi, ebx
	syscall
	inc	rbx
	cmp	rbx, r15
	jl	child_close_loop

	/* Stop and wait for qcore to read /proc/self/mem.  Loop in case we
	 * are spuriously continued. */
child_stop_loop:
#if 0
	mov	eax, 39			/* SYS_getpid                          */
	syscall
	mov	rdi, rax
	mov	esi, 19			/* SIGSTOP                             */
	mov	eax, 62			/* SYS_kill                            */
	syscall
#else
	mov	eax, 34			/* SYS_pause                           */
	syscall
#endif
	jmp	child_stop_loop

parasite_end:
