#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/procfs.h>
#include <elf.h>
#include <limits.h>
#include <sys/resource.h>
#include <time.h>

static inline double qcore_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

#define PAGE_SIZE_DEFAULT 4096UL
#define DA_INIT_CAP 64

/* ---------- Thread tracking ---------------------------------------- */

typedef struct {
    pid_t                   tid;
    struct user_regs_struct regs;
    int                     regs_valid;
    char                    name[16];   /* from /proc/<pid>/task/<tid>/comm */
    pid_t                   ns_tid;     /* innermost-namespace TID; equals tid when not in a container */
} thread_info_t;

typedef struct {
    thread_info_t *data;
    int            count;
    int            capacity;
} thread_set_t;

/* ---------- FD / Socket tracking ------------------------------------ */

typedef enum {
    FD_TYPE_SOCKET_TCP4,
    FD_TYPE_SOCKET_TCP6,
    FD_TYPE_SOCKET_UDP4,
    FD_TYPE_SOCKET_UDP6,
    FD_TYPE_SOCKET_UNIX,
    FD_TYPE_SOCKET_UNKNOWN,
    FD_TYPE_OTHER,
} fd_type_t;

typedef struct {
    int      fd_num;
    char     symlink[512];
    fd_type_t type;
    uint64_t  inode;
    /* Open flags from /proc/<pid>/fdinfo/<fd> */
    int      open_flags;          /* raw O_* value */
    /* File fields (FD_TYPE_OTHER) */
    int64_t  file_pos;            /* seek position; -1 if not applicable */
    int64_t  file_size;           /* size in bytes; -1 if not applicable */
    /* Socket fields */
    char     local_addr[80];   /* big enough for [IPv6]:port */
    char     remote_addr[80];
    uint16_t local_port;
    uint16_t remote_port;
    char     state[24];
    uint32_t recv_q;              /* TCP/UDP receive queue bytes */
    uint32_t send_q;              /* TCP/UDP transmit queue bytes */
    char     unix_path[256];
} fd_info_t;

typedef struct {
    fd_info_t *data;
    int        count;
    int        capacity;
} fd_list_t;

/* ---------- Memory map entry --------------------------------------- */

typedef struct {
    uint64_t start;
    uint64_t end;
    uint32_t flags;    /* PF_R | PF_W | PF_X */
    uint64_t file_offset;
    char     name[256];
} map_entry_t;

typedef struct {
    map_entry_t *data;
    int          count;
    int          capacity;
} map_list_t;

/* ---------- Global dumper state ------------------------------------ */

typedef struct {
    pid_t        target_pid;
    thread_set_t threads;
    fd_list_t    fds;

    /* Operating mode.  0 = safe (default): only inject into a thread at a
     * clean point (user-space, or a syscall-exit reached via the race).
     * 1 = force (-f): inject into any thread even if mid-syscall. */
    int          force;

    /* 1 = compress core output through xz (-c flag). */
    int          compress;

    /* Safe thread: the thread used for parasite injection.
     * Preference: a thread that was in user-space (orig_rax == -1)
     * so restoration is completely clean with no rip-2 restart. */
    int                     safe_thread_idx;
    uint64_t                safe_saved_word;     /* original 8 bytes at RIP */
    struct user_regs_struct safe_saved_regs;     /* original registers      */
    int                     safe_bytes_modified; /* 1 after PTRACE_POKETEXT */

    /* Parasite allocation (3 pages: scratch + child1 stack + code). */
    uint64_t mmap_addr;    /* base address; 0 until allocated              */

    /* Child 2: the orphaned grandchild holding the COW snapshot. */
    pid_t    child2_pid;

    char core_path[256];
    char fds_json_path[256];
    char threads_json_path[256];
} qcore_state_t;

/* ---------- Phase function declarations ---------------------------- */

int  seize_all_threads(qcore_state_t *state);           /* seize.c      */
void write_threads_json(const qcore_state_t *state);    /* fd_harvest.c */
int  harvest_fds(qcore_state_t *state);                 /* fd_harvest.c */
void write_fds_json(const qcore_state_t *state);    /* fd_harvest.c */
int  inject_parasite(qcore_state_t *state);             /* inject.c     */
int  dump_core(qcore_state_t *state);                   /* elf_dump.c   */
