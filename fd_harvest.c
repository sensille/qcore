/*
 * Phase 2 - FD and socket harvesting.
 *
 * While the target is fully frozen we enumerate /proc/<pid>/fd/, classify
 * each descriptor, and cross-reference socket inodes against /proc/net/tcp,
 * /proc/net/tcp6, /proc/net/udp, /proc/net/udp6, and /proc/net/unix to
 * collect local/remote addresses and connection state.
 */
#include "qcore.h"

/* TCP state table (value is the kernel's internal state index, 1-based). */
static const char *TCP_STATES[] = {
    "UNKNOWN",       /* 0  - not used by kernel */
    "ESTABLISHED",   /* 01 */
    "SYN_SENT",      /* 02 */
    "SYN_RECV",      /* 03 */
    "FIN_WAIT1",     /* 04 */
    "FIN_WAIT2",     /* 05 */
    "TIME_WAIT",     /* 06 */
    "CLOSE",         /* 07 */
    "CLOSE_WAIT",    /* 08 */
    "LAST_ACK",      /* 09 */
    "LISTEN",        /* 0A */
    "CLOSING",       /* 0B */
};
#define N_TCP_STATES ((int)(sizeof(TCP_STATES)/sizeof(TCP_STATES[0])))

/* Unix socket type names */
static const char *unix_type_name(unsigned int t) {
    switch (t) {
    case 1: return "STREAM";
    case 2: return "DGRAM";
    case 5: return "SEQPACKET";
    default: return "UNKNOWN";
    }
}

/* Unix socket state names */
static const char *unix_state_name(unsigned int s) {
    switch (s) {
    case 1: return "UNCONNECTED";
    case 2: return "CONNECTING";
    case 3: return "CONNECTED";
    case 4: return "DISCONNECTING";
    default: return "UNKNOWN";
    }
}

/* ------------------------------------------------------------------ */
/* Dynamic array helpers                                               */

static fd_info_t *fd_list_add(fd_list_t *l) {
    if (l->count == l->capacity) {
        int nc = l->capacity ? l->capacity * 2 : DA_INIT_CAP;
        fd_info_t *p = realloc(l->data, (size_t)nc * sizeof(*p));
        if (!p) { perror("realloc fd_list"); return NULL; }
        l->data     = p;
        l->capacity = nc;
    }
    fd_info_t *e = &l->data[l->count++];
    memset(e, 0, sizeof(*e));
    return e;
}

/* ------------------------------------------------------------------ */
/* Convert a hex host-byte-order IPv4 address (as printed by the      */
/* kernel in /proc/net/tcp) to dotted-decimal string.                 */

static void fmt_ipv4(uint32_t host_le, uint16_t port, char *buf, size_t bsz)
{
    struct in_addr ia = { .s_addr = htonl(host_le) };
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ia, ip, sizeof(ip));
    snprintf(buf, bsz, "%s:%u", ip, (unsigned)port);
}

/*
 * The kernel stores IPv6 addresses in /proc/net/tcp6 as four consecutive
 * 32-bit host-byte-order words (total 128 bits, 32 hex chars).
 */
static void fmt_ipv6(const char *hex32, uint16_t port, char *buf, size_t bsz)
{
    uint32_t w[4];
    sscanf(hex32, "%08X%08X%08X%08X", &w[0], &w[1], &w[2], &w[3]);
    /* Convert each word from host to network order */
    uint32_t nb[4] = { htonl(w[0]), htonl(w[1]), htonl(w[2]), htonl(w[3]) };
    char ip[INET6_ADDRSTRLEN];   /* 46 bytes max */
    inet_ntop(AF_INET6, nb, ip, sizeof(ip));
    /* buf must be at least 54 bytes: '[' + 45 + ']:' + 5 + NUL */
    snprintf(buf, bsz, "[%s]:%u", ip, (unsigned)port);
}

/* ------------------------------------------------------------------ */
/* Parse /proc/net/tcp or /proc/net/tcp6 (or udp/udp6) and fill in   */
/* entries whose inodes match sockets we've already identified.        */

static void parse_net_table(fd_list_t *fds, const char *path,
                             fd_type_t type4, fd_type_t type6)
{
    int is_v6 = (type4 != type6);   /* ipv6 paths have v6 flag */
    (void)is_v6;

    FILE *f = fopen(path, "r");
    if (!f) return;   /* path might not exist (e.g., no IPv6) */

    char line[512];
    char *_hdr __attribute__((unused)) = fgets(line, sizeof(line), f);

    while (fgets(line, sizeof(line), f)) {
        /* Layout (v4): sl local_addr:port remote_addr:port st ... inode */
        unsigned int sl, st, uid, timeout;
        uint64_t inode;
        char laddr[80], raddr[80];   /* [IPv6]:port needs up to 54 bytes */
        uint16_t lport, rport;

        int n;
        if (type4 == FD_TYPE_SOCKET_TCP4 || type4 == FD_TYPE_SOCKET_UDP4) {
            /* IPv4: 8-char hex address */
            uint32_t la, ra;
            n = sscanf(line,
                " %u: %8X:%4hX %8X:%4hX %2X %*X:%*X %*X:%*X %*X %u %u %lu",
                &sl, &la, &lport, &ra, &rport, &st, &uid, &timeout, &inode);
            if (n < 9) continue;
            fmt_ipv4(la, lport, laddr, sizeof(laddr));
            fmt_ipv4(ra, rport, raddr, sizeof(raddr));
        } else {
            /* IPv6: 32-char hex address */
            char lhex[33], rhex[33];
            n = sscanf(line,
                " %u: %32s %32s %2X %*X:%*X %*X:%*X %*X %u %u %lu",
                &sl, lhex, rhex, &st, &uid, &timeout, &inode);
            if (n < 7) continue;
            /* Addresses include port: split at ':' */
            char *lc = strrchr(lhex, ':');
            char *rc = strrchr(rhex, ':');
            if (!lc || !rc) continue;
            *lc = *rc = '\0';
            sscanf(lc+1, "%4hX", &lport);
            sscanf(rc+1, "%4hX", &rport);
            fmt_ipv6(lhex, lport, laddr, sizeof(laddr));
            fmt_ipv6(rhex, rport, raddr, sizeof(raddr));
        }

        const char *state_str = (st < (unsigned)N_TCP_STATES) ? TCP_STATES[st] : "UNKNOWN";

        /* Find all FD entries that match this inode */
        for (int i = 0; i < fds->count; i++) {
            fd_info_t *fi = &fds->data[i];
            if (fi->inode != inode) continue;
            if (fi->type != FD_TYPE_SOCKET_UNKNOWN) continue;

            fi->type       = type4;   /* v4 or v6 determined by which file we parsed */
            fi->local_port = lport;
            fi->remote_port= rport;
            strncpy(fi->local_addr,  laddr, sizeof(fi->local_addr));
            strncpy(fi->remote_addr, raddr, sizeof(fi->remote_addr));
            strncpy(fi->state,       state_str, sizeof(fi->state));
        }
    }
    fclose(f);
}

/* Parse /proc/net/unix and match entries to our socket inodes. */
static void parse_net_unix(fd_list_t *fds, pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/net/unix", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return;

    char line[512];
    char *_hdr2 __attribute__((unused)) = fgets(line, sizeof(line), f);

    while (fgets(line, sizeof(line), f)) {
        /* Num RefCount Protocol Flags Type St Inode Path */
        uint64_t inode;
        unsigned int refcnt, proto, flags, type, st;
        char path[256] = "";

        int n = sscanf(line,
            "%*s %u %u %X %X %X %lu %255[^\n]",
            &refcnt, &proto, &flags, &type, &st, &inode, path);
        if (n < 6) continue;

        /* Trim leading space from path */
        char *p = path;
        while (*p == ' ') p++;

        for (int i = 0; i < fds->count; i++) {
            fd_info_t *fi = &fds->data[i];
            if (fi->inode != inode) continue;
            if (fi->type  != FD_TYPE_SOCKET_UNKNOWN) continue;

            fi->type = FD_TYPE_SOCKET_UNIX;
            snprintf(fi->state, sizeof(fi->state), "%s/%s",
                     unix_state_name(st), unix_type_name(type));
            strncpy(fi->unix_path, p, sizeof(fi->unix_path));
        }
    }
    fclose(f);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */

int harvest_fds(qcore_state_t *state)
{
    char fd_dir[64];
    snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", (int)state->target_pid);

    DIR *d = opendir(fd_dir);
    if (!d) {
        fprintf(stderr, "opendir(%s): %s\n", fd_dir, strerror(errno));
        return -1;
    }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.')
            continue;

        int fd_num = atoi(ent->d_name);
        if (fd_num < 0)
            continue;

        char fd_path[128];
        snprintf(fd_path, sizeof(fd_path), "%s/%d", fd_dir, fd_num);

        char target[512];
        ssize_t len = readlink(fd_path, target, sizeof(target) - 1);
        if (len < 0)
            continue;
        target[len] = '\0';

        fd_info_t *fi = fd_list_add(&state->fds);
        if (!fi) { closedir(d); return -1; }

        fi->fd_num = fd_num;
        strncpy(fi->symlink, target, sizeof(fi->symlink));

        if (strncmp(target, "socket:[", 8) == 0) {
            uint64_t inode = 0;
            sscanf(target + 8, "%lu", &inode);
            fi->inode = inode;
            fi->type  = FD_TYPE_SOCKET_UNKNOWN;   /* resolve below */
        } else {
            fi->type = FD_TYPE_OTHER;
        }
    }
    closedir(d);

    /* Read network tables from the target's own network namespace via
     * /proc/<pid>/net/ so that containerised processes (which live in a
     * separate netns) are handled correctly. */
    pid_t pid = state->target_pid;
    char tcp_path[64], tcp6_path[64], udp_path[64], udp6_path[64];
    snprintf(tcp_path,  sizeof(tcp_path),  "/proc/%d/net/tcp",  (int)pid);
    snprintf(tcp6_path, sizeof(tcp6_path), "/proc/%d/net/tcp6", (int)pid);
    snprintf(udp_path,  sizeof(udp_path),  "/proc/%d/net/udp",  (int)pid);
    snprintf(udp6_path, sizeof(udp6_path), "/proc/%d/net/udp6", (int)pid);
    parse_net_table(&state->fds, tcp_path,  FD_TYPE_SOCKET_TCP4, FD_TYPE_SOCKET_TCP4);
    parse_net_table(&state->fds, tcp6_path, FD_TYPE_SOCKET_TCP6, FD_TYPE_SOCKET_TCP6);
    parse_net_table(&state->fds, udp_path,  FD_TYPE_SOCKET_UDP4, FD_TYPE_SOCKET_UDP4);
    parse_net_table(&state->fds, udp6_path, FD_TYPE_SOCKET_UDP6, FD_TYPE_SOCKET_UDP6);
    parse_net_unix(&state->fds, pid);

    printf("[phase2] harvested %d file descriptor(s)\n", state->fds.count);
    return 0;
}

/* ------------------------------------------------------------------ */
/* JSON output                                                         */

static const char *fd_type_to_str(fd_type_t t) {
    switch (t) {
    case FD_TYPE_SOCKET_TCP4:    return "tcp4";
    case FD_TYPE_SOCKET_TCP6:    return "tcp6";
    case FD_TYPE_SOCKET_UDP4:    return "udp4";
    case FD_TYPE_SOCKET_UDP6:    return "udp6";
    case FD_TYPE_SOCKET_UNIX:    return "unix";
    case FD_TYPE_SOCKET_UNKNOWN: return "socket_unknown";
    case FD_TYPE_OTHER:          return "file";
    default:                     return "unknown";
    }
}

/* Emit a JSON-safe string (escape backslash and double-quote). */
static void json_str(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') fputc('\\', f);
        fputc(*s, f);
    }
    fputc('"', f);
}

void write_fds_json(const qcore_state_t *state)
{
    FILE *f = fopen(state->fds_json_path, "w");
    if (!f) {
        fprintf(stderr, "fopen(%s): %s\n", state->fds_json_path, strerror(errno));
        return;
    }

    fprintf(f, "{\n  \"pid\": %d,\n  \"fds\": [\n", (int)state->target_pid);

    for (int i = 0; i < state->fds.count; i++) {
        const fd_info_t *fi = &state->fds.data[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"fd\": %d,\n", fi->fd_num);
        fprintf(f, "      \"type\": \"%s\"", fd_type_to_str(fi->type));

        switch (fi->type) {
        case FD_TYPE_SOCKET_TCP4:
        case FD_TYPE_SOCKET_TCP6:
        case FD_TYPE_SOCKET_UDP4:
        case FD_TYPE_SOCKET_UDP6:
            fprintf(f, ",\n      \"local\": ");  json_str(f, fi->local_addr);
            fprintf(f, ",\n      \"remote\": "); json_str(f, fi->remote_addr);
            fprintf(f, ",\n      \"state\": ");  json_str(f, fi->state);
            break;
        case FD_TYPE_SOCKET_UNIX:
            fprintf(f, ",\n      \"path\": ");   json_str(f, fi->unix_path);
            fprintf(f, ",\n      \"state\": ");  json_str(f, fi->state);
            break;
        case FD_TYPE_SOCKET_UNKNOWN:
            fprintf(f, ",\n      \"inode\": %lu", (unsigned long)fi->inode);
            break;
        case FD_TYPE_OTHER:
            fprintf(f, ",\n      \"path\": ");   json_str(f, fi->symlink);
            break;
        }

        fprintf(f, "\n    }");
        if (i + 1 < state->fds.count) fputc(',', f);
        fputc('\n', f);
    }

    fprintf(f, "  ]\n}\n");
    fclose(f);
    printf("[phase5] wrote fd info to %s\n", state->fds_json_path);
}

void write_threads_json(const qcore_state_t *state)
{
    FILE *f = fopen(state->threads_json_path, "w");
    if (!f) {
        fprintf(stderr, "fopen(%s): %s\n",
                state->threads_json_path, strerror(errno));
        return;
    }

    fprintf(f, "{\n  \"pid\": %d,\n  \"threads\": [\n",
            (int)state->target_pid);

    for (int i = 0; i < state->threads.count; i++) {
        const thread_info_t *t = &state->threads.data[i];
        fprintf(f, "    {\"tid\": %d", (int)t->tid);
        if (t->ns_tid != t->tid)
            fprintf(f, ", \"ns_tid\": %d", (int)t->ns_tid);
        fprintf(f, ", \"name\": ");
        json_str(f, t->name[0] ? t->name : "");
        fprintf(f, "}");
        if (i + 1 < state->threads.count) fputc(',', f);
        fputc('\n', f);
    }

    fprintf(f, "  ]\n}\n");
    fclose(f);
    printf("[phase5] wrote thread names to %s\n", state->threads_json_path);
}
