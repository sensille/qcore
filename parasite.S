/*
 * qcore parasite - x86-64 position-independent shellcode
 *
 * Receives: %r15 = base of the 3-page allocation made by qcore (RWX):
 *
 *   Page 0  [%r15 + 0    .. %r15 + 4095]   scratch
 *     offset 0:  u64 child2_pid   <- written by Child 1, read by Parent spin
 *
 *   Page 1  [%r15 + 4096 .. %r15 + 8191]   Child 1's private stack
 *     top of stack = %r15 + 8176  (16-byte aligned, passed as child_stack)
 *
 *   Page 2  [%r15 + 8192 .. %r15 + 12287]  this code (%rip starts here)
 *
 * Execution flow (three code paths separated by fork return values):
 *
 * PARENT (%rax > 0 after first clone):
 *   Spin on scratch[0] until Child 1 writes child2_pid, then int3.
 *   qcore catches the trap, reads %rax = child2_pid, restores registers.
 *
 * CHILD 1 (%rax == 0 after first clone):
 *   Perform second clone (flags=0 = full COW snapshot of parent).
 *   If still Child 1: write child2_pid to scratch[0], SYS_exit(0).
 *   If Child 2: fall through to fd-scrub + SIGSTOP path.
 *
 * CHILD 2 (%rax == 0 after second clone):
 *   Close fds 0-1023 to prevent our SIGKILL from triggering io_uring
 *   teardowns, POSIX lock drops, or TCP RST/FIN refcount cascades.
 *   Then loop on kill(self, SIGSTOP) waiting for qcore to snapshot us.
 *
 * Why CLONE_VM for the first fork:
 *   CLONE_VM makes Child 1 share the parent's physical pages without COW.
 *   A write to scratch[0] in Child 1 is therefore *immediately* visible to
 *   the parent without IPC, pipes, or any barrier instruction.  The exit
 *   signal byte (flags & 0xFF = 0x100 & 0xFF = 0) suppresses SIGCHLD.
 *
 *   When Child 1 performs the *second* clone (flags=0), Child 2 receives a
 *   standard COW snapshot of the parent's address space -- which is the
 *   same as Child 1's address space due to CLONE_VM.  So Child 2 is a
 *   correct memory snapshot of the target.
 *
 * Why CLONE_VM is safe here:
 *   Child 1 only writes to scratch[0] (our controlled area) before exiting.
 *   It never touches any other part of the address space.
 */

	.intel_syntax noprefix
	.text
	.global parasite_start
	.global parasite_end

parasite_start:

/* ------------------------------------------------------------------ */
/* First clone: CLONE_VM so Child 1 can write back via shared memory   */
/* ------------------------------------------------------------------ */

	mov	eax, 56			/* SYS_clone                          */
	mov	edi, 0x100		/* CLONE_VM; exit_signal byte = 0     */
	lea	rsi, [r15 + 8176]	/* child_stack: top of page 1 stack   */
	xor	edx, edx		/* ptid  = NULL                       */
	xor	r10d, r10d		/* ctid  = NULL                       */
	xor	r8d, r8d		/* tls   = NULL                       */
	syscall

	test	rax, rax
	jnz	.parent			/* rax > 0 -> we are the parent       */

/* ------------------------------------------------------------------ */
/* Child 1: create COW snapshot (Child 2), then exit                   */
/* ------------------------------------------------------------------ */

	/* Second clone: flags=0 gives Child 2 a full COW copy of the
	 * parent's address space.  child_stack=0 inherits our RSP (which
	 * is in the dedicated stack page, safely separated from scratch). */
	mov	eax, 56			/* SYS_clone                          */
	xor	edi, edi		/* flags=0: COW + exit_signal=0       */
	xor	esi, esi		/* child_stack = 0                    */
	xor	edx, edx
	xor	r10d, r10d
	xor	r8d, r8d
	syscall

	test	rax, rax
	jnz	.child1_store		/* rax > 0 -> still Child 1           */

/* ------------------------------------------------------------------ */
/* Child 2: fd scrub then pause                                         */
/* ------------------------------------------------------------------ */

	/* Close every fd 0..1023.  The kernel silently ignores EBADF.
	 * This prevents our eventual SIGKILL from:
	 *   - decrementing TCP socket refcounts (=> RST/FIN to remote)
	 *   - triggering io_uring ring teardown side-effects
	 *   - dropping POSIX advisory file locks                        */
	xor	ebx, ebx
.close_fd:
	mov	eax, 3			/* SYS_close                          */
	mov	edi, ebx
	syscall
	inc	ebx
	cmp	ebx, 1024
	jl	.close_fd

	/* Stop; qcore will PTRACE_ATTACH us and read /proc/self/mem.
	 * Loop in case we are accidentally continued.                    */
.stop_loop:
	mov	eax, 39			/* SYS_getpid                         */
	syscall
	mov	rdi, rax		/* pid = self                         */
	mov	esi, 19			/* SIGSTOP                            */
	mov	eax, 62			/* SYS_kill                           */
	syscall
	jmp	.stop_loop

/* ------------------------------------------------------------------ */
/* Child 1 cleanup: communicate child2_pid, then exit                  */
/* ------------------------------------------------------------------ */
.child1_store:
	/* rax = child2_pid.  Write to scratch[0].
	 * The write is immediately visible to the parent because CLONE_VM
	 * means we share the same physical page.                         */
	mov	QWORD PTR [r15], rax

	/* Exit Child 1 (SYS_exit = single-thread exit, not exit_group). */
	xor	edi, edi
	mov	eax, 60			/* SYS_exit                           */
	syscall

/* ------------------------------------------------------------------ */
/* Parent: spin until child2_pid is written, then signal qcore         */
/* ------------------------------------------------------------------ */
.parent:
	/* PAUSE reduces pipeline speculation overhead in tight spin loops. */
.spin:
	pause
	mov	rax, QWORD PTR [r15]	/* read child2_pid from scratch[0]    */
	test	rax, rax
	jz	.spin

	/* rax = child2_pid.  Trap into qcore via software breakpoint.
	 * qcore will read rax, then restore our original rip/registers.  */
	int3

	/* Unreachable: qcore restores rip before PTRACE_DETACH.          */
	ud2

parasite_end:
