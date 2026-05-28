# Why the COW fork-injection approach does not work reliably

The architecture in prompt.txt is theoretically elegant but breaks down in practice
against any non-trivial production process. This document explains the specific
failure modes we encountered.

---

## 1. Phase 1: PTRACE_ATTACH sends SIGSTOP to every thread

The prompt specifies `ptrace(PTRACE_ATTACH, tid)`, which works by delivering SIGSTOP
to each thread. This seems harmless, but:

- Even though ptrace *consumes* the stop signal on detach, the signal-delivery
  machinery still runs inside the kernel for every thread on every attach/detach
  cycle. It disturbs futex wait-queue registrations, pending-signal bookkeeping, and
  signal masks in subtle ways.
- These effects **accumulate** across repeated runs. A server process that survived
  run 1 crashed on run 4 because some internal counter or retry limit was exhausted.
- The fix is `PTRACE_SEIZE + PTRACE_INTERRUPT`, which stops threads via an internal
  ptrace mechanism that never touches the signal path. We implemented this, but it
  does not resolve the core problem (see below).

---

## 2. Phase 3: Injecting a syscall into a live thread is fundamentally disruptive

This is the central flaw. The prompt instructs:

> Overwrite the instructions at %rip with the machine code for a syscall instruction.
> Modify the thread's registers to invoke sys_fork. Use PTRACE_SINGLESTEP.

A thread that is blocked in a blocking syscall (epoll_wait, futex, io_uring_enter,
read, nanosleep, ...) when ptrace stops it has:

- `rip` pointing to the instruction *after* the syscall opcode in libc
- `rax` containing a kernel-internal restart code (ERESTARTSYS = -512,
  ERESTARTNOHAND = -514, etc.)
- `orig_rax` containing the original syscall number

When we execute our injected clone() via PTRACE_SINGLESTEP, the kernel clears the
"syscall restart pending" task flags for that thread (a new syscall just completed).
After we restore the original registers, those flags are gone. The thread's original
blocking syscall cannot be transparently restarted.

**Attempted fixes and why they all failed:**

### Fix A: Convert restart codes to -EINTR before PTRACE_DETACH

The injected thread's blocking call returns -EINTR to user space. For a worker
thread in pthread_mutex_lock this is transparent (pthreads retries internally). For
the main event-loop thread (epoll_wait, io_uring_enter) it is not:

- Ceph RGW: the S3 signature validation uses in-flight HMAC state spread across
  cooperating threads. The event-loop thread returning -EINTR at an unexpected point
  corrupted the handoff between threads, producing "SignatureDoesNotMatch" errors.
- Some applications have retry limits (e.g. "if epoll_wait returns EINTR more than N
  times in a row, abort"). Four successive qcore runs exhausted such a counter.

### Fix B: Rewind the thread to re-execute its original syscall (rip -= 2)

On x86-64 the `syscall` opcode is always 2 bytes, so `saved_rip - 2` is always the
syscall instruction. Setting `rip = saved_rip - 2` and `rax = orig_rax` causes the
thread to re-enter the original blocking call as if nothing happened.

This eliminates -EINTR for the injector thread, but it broke Ceph more reliably
(2/2 runs) than the -EINTR approach (1/4 runs). The likely reason: for syscalls
with observable side effects that partially completed before the stop
(io_uring_enter submitting some SQEs, a partial write, etc.), re-executing them
causes double-submission or other state corruption. We cannot know from outside the
process which syscalls are safe to restart from scratch.

### Fix C: Prefer a non-main thread as the injector

Reasoning: worker threads in futex_wait handle spurious wakeups transparently via
pthreads. But the choice of injector thread does not eliminate the problem; it
merely changes which code path is affected. For a 623-thread Ceph RGW with all
threads blocked in syscalls, there is no safe injector thread.

---

## 3. Phase 3: fork() / clone() itself has global side effects

Calling `sys_clone()` from within a production process triggers effects beyond the
thread's register state:

**OpenSSL fork-safety:**  
Ceph uses OpenSSL with custom locking callbacks (`CRYPTO_set_locking_callback`,
`CRYPTO_set_id_callback`). OpenSSL pre-1.1.1 and some post-1.1.1 builds assume that
after fork() the child is either single-threaded or immediately calls exec(). A
frozen-but-alive COW child holding all the parent's OpenSSL contexts and lock state
puts the parent's OpenSSL subsystem in an undefined post-fork state, even though the
child never executes a single user-space instruction.

**pthread_atfork handlers are NOT invoked:**  
Because we call `sys_clone()` directly (bypassing libc's `fork()` wrapper), no
`pthread_atfork` prepare/parent/child handlers run. Libraries that rely on these to
reinitialize state after fork (jemalloc, OpenSSL, some gRPC internals, etc.) are
left in an inconsistent state in the parent.

**The child appears in the parent's process tree:**  
Even with `exit_signal = 0` (CLONE_FILES & 0xFF = 0), the child exists as a process
under the target's PID namespace and is visible in /proc. Some frameworks
(Erlang/OTP, Ceph's own internal watchdogs) actively scan their child process list
and abort when they find unexpected entries.

---

## 4. Phase 4: There is no safe moment to detach

The window between "inject clone()" and "PTRACE_DETACH all threads" is the most
dangerous part of the operation:

- The injector thread's text has been modified (syscall opcode at rip).
- Its registers have been modified (rax = SYS_clone).
- A new child process exists with all the parent's open file descriptors,
  memory-mapped files, and synchronisation primitives.

If qcore receives a signal (SIGINT from Ctrl-C, SIGTERM from the OS) in this window,
the parent process dies with corrupted text/registers and a zombie COW child. We
added an emergency signal handler, but async-signal-safe code cannot replicate the
full register-restore + rip-2 restart logic safely.

---

## 5. Phase 6: Killing the clone has delayed side effects

`kill(child_pid, SIGKILL)` triggers the kernel's process teardown for the child:

- **Without CLONE_FILES:** The child has a *copy* of the fd table. Every fd
  (including live TCP sockets) has its refcount decremented. If the parent closed any
  fd between Phase 3 (clone) and Phase 6 (kill), that fd's refcount hits zero and the
  underlying file is closed. For TCP sockets this sends RST or FIN to the remote end
  -- up to hundreds of milliseconds after the parent thought it had closed them. This
  broke S3 upload operations in Ceph.
- **With CLONE_FILES** (our fix): the shared fd table's refcount drops from 2 to 1,
  no individual fds are closed. But CLONE_FILES brings its own complications (see
  section 3 above: the child inherits io_uring ring fds, event fds, etc.).

---

## Summary

The prompt's design assumes that a frozen thread is a neutral observer with no
ongoing state commitments. In practice, every thread blocked in a kernel syscall is
in the middle of a contract with the kernel (a futex wait, an io_uring ring drain, a
socket read). Injecting an unrelated syscall (clone/fork) into that thread tears up
the contract in ways that:

1. Cannot be made transparent by any register-restore strategy, because the kernel's
   internal per-task flags (restart_block, TIF_SIGPENDING variants) are cleared when
   a new syscall completes.
2. Have library-level side effects (OpenSSL, pthreads, jemalloc) that fire on
   fork() regardless of what the child does.
3. Change the observable state of the process (new child PID, fd refcounts) in ways
   that can be detected and acted upon by the target application.

The only truly non-disruptive snapshot approach is to read `/proc/<pid>/mem` while
the threads are frozen (before any injection), accepting a longer freeze window in
exchange for zero side effects. This is what `gcore` does, and it is the correct
design for this problem.
