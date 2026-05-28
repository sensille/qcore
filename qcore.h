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

#define PAGE_SIZE_DEFAULT 4096UL
#define DA_INIT_CAP 64

/* ---------- Thread tracking ---------------------------------------- */

typedef struct {
    pid_t                   tid;
    struct user_regs_struct regs;
    int                     regs_valid;
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
    /* Socket fields */
    char     local_addr[80];   /* big enough for [IPv6]:port */
    char     remote_addr[80];
    uint16_t local_port;
    uint16_t remote_port;
    char     state[24];
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
    pid_t        child_pid;

    /* Injector thread bookkeeping (for Phase 3/4) */
    int                     injector_idx;
    uint64_t                injector_saved_word;     /* 8 bytes at original RIP */
    struct user_regs_struct injector_saved_regs;
    int                     injector_bytes_modified; /* 1 once we wrote syscall opcode */

    char core_path[256];
    char sockets_json_path[256];
} qcore_state_t;

/* ---------- Phase function declarations ---------------------------- */

int  seize_all_threads(qcore_state_t *state);           /* seize.c      */
int  harvest_fds(qcore_state_t *state);                 /* fd_harvest.c */
void write_sockets_json(const qcore_state_t *state);    /* fd_harvest.c */
int  cow_clone(qcore_state_t *state);                   /* cow_clone.c  */
int  resume_parent(qcore_state_t *state);               /* resume.c     */
int  dump_core(qcore_state_t *state);                   /* elf_dump.c   */
