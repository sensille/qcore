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
 * Double-fork rationale
 * ---------------------
 *   First clone (CLONE_VM) creates Child 1, which shares the parent's
 *   address space so it can write Child 2's PID straight back to the
 *   scratch page with no IPC.  Child 1 then clones Child 2 (a copy-on-write
 *   snapshot) and exits, orphaning Child 2.
 *
 *   Child 2 is created with exit_signal = SIGCHLD so that whatever process
 *   adopts it (init, or a subreaper such as a container's init) is notified
 *   and reaps it after qcore kills it.  With exit_signal = 0 a signal-driven
 *   reaper is never woken and Child 2 lingers as a zombie.
 *
 *   Child 1 is reaped explicitly by the parent (injector) with wait4 before
 *   the int3 trap.  Child 1 was created with CLONE_VM and exit_signal = 0,
 *   so the wait4 must pass __WALL -- waitpid only matches SIGCHLD children
 *   otherwise and would return ECHILD, leaving Child 1 a zombie.
 *
 * Execution paths
 * ---------------
 * PARENT (%rax > 0 after first clone):
 *   Spin on scratch[0] with a finite counter in %r13 (~10M iterations).
 *   On timeout write -1 and int3 so qcore can detect failure and restore.
 *   On success: reap Child 1, load child2_pid into %rax, int3.
 *
 * CHILD 1 (%rax == 0 after first clone):
 *   Second clone (exit_signal=SIGCHLD) -> Child 2.  Write the result
 *   (positive PID or negative errno) to scratch[0] and exit.
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
 * exit_signal byte = 0x100 & 0xff = 0 (no SIGCHLD to parent; Child 1 is
 * reaped explicitly with wait4 below).                                 */

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
/* Child 2 is created with exit_signal = SIGCHLD (17) so that init or any
 * adopting subreaper is notified and reaps it after qcore's SIGKILL.    */

	mov	eax, 56			/* SYS_clone                           */
	mov	edi, 17			/* flags: exit_signal=SIGCHLD, COW copy */
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

/* ---- Parent: spin with timeout, then reap Child 1, then int3 ------ */
parent_path:
	/* Handle the case where the first clone() itself failed (rax < 0).
	 * Write the error code to scratch[0] and fall through to int3 so
	 * qcore receives rax < 0 and can abort cleanly.                   */
	test	rax, rax
	js	parent_clone_failed

	/* Save Child 1's PID so we can wait4() on it after the spin.
	 * rbx is callee-saved and unused elsewhere in this code path;
	 * qcore restores all registers from safe_saved_regs anyway.       */
	mov	rbx, rax

	/* Load a spin counter.  ~10M iterations takes well under a second
	 * on any modern CPU.  If Child 1 doesn't write child2_pid in time
	 * (OOM-kill, kernel bug, etc.) we write -1 and trap so qcore can
	 * restore the thread rather than deadlocking the target process.  */
	mov	r13, 10000000
parent_spin:
	pause
	mov	rax, QWORD PTR [r15]
	test	rax, rax
	jnz	parent_reap_child1	/* Child 1 wrote child2_pid           */
	dec	r13
	jnz	parent_spin

	/* Timeout: Child 1 never wrote child2_pid (OOM-killed, etc.).
	 * Try a non-blocking wait4 to prevent a zombie if it has exited.
	 * Child 1 has exit_signal=0, so __WALL is required.               */
	mov	QWORD PTR [r15], -1
	mov	edi, ebx		/* pid = child1_pid                    */
	xor	esi, esi		/* wstatus = NULL                      */
	mov	edx, 0x40000001		/* __WALL | WNOHANG                    */
	xor	r10d, r10d		/* rusage = NULL                       */
	mov	eax, 61			/* SYS_wait4                           */
	syscall
	mov	rax, -1			/* sentinel for qcore                  */
	jmp	parent_trap

parent_reap_child1:
	/* Child 1 has written child2_pid to scratch[0] and is about to
	 * call SYS_exit.  A blocking wait4 returns in microseconds and
	 * prevents Child 1 from lingering as a zombie in the target's
	 * child list.  Save child2_pid in r12 across the syscall.
	 * Child 1 has exit_signal=0, so __WALL is required.               */
	mov	r12, rax		/* r12 = child2_pid                    */
	mov	edi, ebx		/* pid = child1_pid                    */
	xor	esi, esi		/* wstatus = NULL                      */
	mov	edx, 0x40000000		/* options = __WALL                    */
	xor	r10d, r10d		/* rusage = NULL                       */
	mov	eax, 61			/* SYS_wait4                           */
	syscall
	mov	rax, r12		/* rax = child2_pid for qcore          */
	jmp	parent_trap

parent_clone_failed:
	/* First clone() failed; rax holds the negative errno.             */
	mov	QWORD PTR [r15], rax

parent_trap:
	int3

	/* Unreachable: qcore restores rip/regs before PTRACE_DETACH.      */
	ud2

parasite_end:
