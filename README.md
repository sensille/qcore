# qcore

Zero-pause core dumper for Linux x86-64.

`gcore` freezes a process for the entire duration of disk I/O  -  tens of seconds for a multi-gigabyte production process. `qcore` freezes it only long enough to take a memory snapshot (typically under 100 ms), resumes it immediately, then writes the core file while the process is already running again.

## Usage

```
qcore [-f] [-c] <pid>
```

| Flag | Effect |
|------|--------|
| *(none)* | Safe mode: waits for a clean injection point (syscall-exit boundary) |
| `-f` | Force mode: inject into any thread regardless of current syscall state |
| `-c` | Compress: pipe the core through `xz -0`, write `core.<pid>.xz` |
| `-t` | Print a detailed theory of operation and exit |

**Output files**

| File | Content |
|------|---------|
| `core.<pid>` | ELF64 core, loadable by GDB/LLDB |
| `core.<pid>.fds.json` | All open file descriptors with type, flags, socket state, recv/send queue depths, file position and size |
| `core.<pid>.threads.json` | Thread names; for containerised targets also the namespace-local TID |

Requires root or `CAP_SYS_PTRACE`.

## How it works

### Phase 1  -  Seize all threads *(target frozen)*

All threads are attached with `PTRACE_SEIZE` + `PTRACE_INTERRUPT`. Unlike `PTRACE_ATTACH`, this sends no signal; threads are stopped via an internal kernel mechanism invisible to the application's signal handling. GP registers are saved from every thread; these become the `NT_PRSTATUS` notes in the core.

FD and socket information is harvested from `/proc/<pid>/fd/` and `/proc/<pid>/net/`.

### Phase 2  -  Find a clean injection thread *(target frozen)*

The snapshot is created by running a small shellcode payload inside the target. One thread (the *injector*) is borrowed for this; the cleanest choice is one that was executing user-space code when stopped, because restoring its registers afterwards is a perfect no-op.

**Safe mode (default):** if no user-space thread exists, all threads are released under `PTRACE_SYSCALL` tracing  -  the process runs normally  -  and qcore waits for any thread to reach the exit of a system call. That thread is then frozen and used as the injector. If no thread reaches a clean exit within the timeout (default 10 s), qcore refuses and suggests `-f`.

**Force mode (`-f`):** inject into any thread. An interrupted syscall returns `-EINTR` on resume, identical to a normal signal delivery.

### Phase 3  -  Parasite injection and fork *(target frozen)*

qcore injects an `mmap` syscall to allocate executable memory in the target, writes the parasite shellcode there, and releases the injector with `PTRACE_CONT`.

The shellcode performs a single `clone()`:

- **Parent (injector):** the child PID is returned in `%rax`. The injector executes `int3`; qcore catches the `SIGTRAP` and reads the PID.
- **Child:** receives a copy-on-write snapshot of the target's entire address space at this instant  -  the basis of the core. It closes all file descriptors (preventing TCP RST/FIN, io\_uring teardown, or lock drops on the eventual `SIGKILL`), then loops on `SIGSTOP` waiting for qcore to read its memory.

### Phase 4  -  Resume the target *(freeze ends)*

qcore injects a `munmap` syscall to free the parasite pages, restores the injector's original registers, and `PTRACE_DETACH`s every thread. The target is running normally again. Total freeze time is typically under 100 ms.

### Phase 5  -  Build the core file *(target running)*

qcore attaches to the child and reads `/proc/<child>/maps` and `/proc/<child>/mem`, streaming the contents into a valid ELF64 core file. ELF notes use the registers saved in Phase 1 from the *target*, not the child's registers, so every thread's backtrace reflects the exact moment of the freeze.

Notes written: `NT_PRSTATUS` (one per thread), `NT_PRPSINFO`, `NT_AUXV` (required for GDB to place PIE binaries  -  without it all frames appear as `?? ()`), `NT_FILE`.

### Phase 6  -  Kill the child

The child receives `SIGKILL`. Because all its fds were closed in Phase 3, the kill has no side effects.

### Phase 7  -  Reap the child *(brief second freeze)*

The child is a direct child of the target; only the target  -  as its real parent  -  can release the resulting zombie. qcore re-freezes all threads, injects `wait4()` into a clean thread so the target reaps the zombie, then detaches. All threads must be frozen during the injection because the opcode is patched into shared executable memory; a running thread hitting the patched bytes would take `SIGILL`.

## Build

```sh
make
sudo make -C test
```

Dependencies: `gcc`, `binutils` (`objcopy`, `as`), `xxd`. GDB and `xz` are optional (tests, `-c` flag).

Tested on Linux 5.15+ x86-64.

## Limitations

**Architecture:** x86-64 Linux only. The parasite shellcode and ELF construction are architecture-specific.

**Privileges:** requires `CAP_SYS_PTRACE`. Cross-namespace ptrace (containerised targets) additionally requires `CAP_SYS_ADMIN` or a permissive `ptrace_scope` (`/proc/sys/kernel/yama/ptrace_scope`).

**Child is briefly visible:** during Phase 5, the snapshot child is a direct child of the target. Process-tree monitors that audit unexpected children will observe it for the duration of the core dump (seconds).

**Memory vs register snapshot time:** the thread register state (Phase 1) and the memory snapshot (Phase 3 clone) are taken a few milliseconds apart. Memory written by other threads between Phase 1 and Phase 3 will be in the core but not reflected in any thread's saved registers.

**No kernel threads:** kernel threads cannot be ptrace-attached and are silently skipped.

**One core at a time:** running two qcore instances against the same target simultaneously will corrupt both cores and likely crash the target.

**`-c` requires `xz`:** compression is done by piping through an external `xz` process; `xz` must be in `PATH`.

**Processes with `PR_SET_DUMPABLE=0`:** ptrace will fail with `EPERM`.

## License

Apache 2.0  -  see [LICENSE](LICENSE).
