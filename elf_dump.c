/*
 * Phase 5 - Build a valid ELF64 core file from the COW child.
 *
 * File layout
 * -----------
 *   [ Elf64_Ehdr                              ]  64 bytes
 *   [ Elf64_Phdr[0]  - PT_NOTE               ]  56 bytes
 *   [ Elf64_Phdr[1]  - PT_LOAD[0]            ]  56 bytes
 *   [ ...                                     ]
 *   [ Elf64_Phdr[N]  - PT_LOAD[N-1]          ]  56 bytes
 *   < padding to align note data to 4 bytes  >
 *   [ NOTE data (NT_PRSTATUS * nthreads +      ]
 *     NT_PRPSINFO + NT_FILE)                  ]
 *   < padding to next page boundary           >
 *   [ PT_LOAD[0] raw memory                   ]
 *   [ PT_LOAD[1] raw memory                   ]
 *   [ ...                                     ]
 *
 * NT_PRSTATUS carries the registers harvested from the PARENT threads in
 * Phase 1, not the child's registers (per spec).
 */
#include "qcore.h"
#include <sys/uio.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                             */

static inline uint64_t align_up(uint64_t v, uint64_t a) {
    return (v + a - 1) & ~(a - 1);
}

/* Write exactly n bytes, retry on short writes. */
static int write_all(int fd, const void *buf, size_t n) {
    const char *p = buf;
    while (n) {
        ssize_t r = write(fd, p, n);
        if (r <= 0) { perror("write"); return -1; }
        p += r; n -= (size_t)r;
    }
    return 0;
}

static int write_zeros(int fd, size_t n) {
    char zero[4096];
    memset(zero, 0, sizeof(zero));
    while (n) {
        size_t chunk = n < sizeof(zero) ? n : sizeof(zero);
        if (write_all(fd, zero, chunk) < 0) return -1;
        n -= chunk;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* /proc/<pid>/maps parsing                                            */

static map_entry_t *map_list_add(map_list_t *l) {
    if (l->count == l->capacity) {
        int nc = l->capacity ? l->capacity * 2 : DA_INIT_CAP;
        map_entry_t *p = realloc(l->data, (size_t)nc * sizeof(*p));
        if (!p) { perror("realloc map_list"); return NULL; }
        l->data     = p;
        l->capacity = nc;
    }
    map_entry_t *e = &l->data[l->count++];
    memset(e, 0, sizeof(*e));
    return e;
}

static int parse_maps(pid_t pid, map_list_t *maps) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) { perror("fopen maps"); return -1; }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        uint64_t start, end, file_off;
        char perms[8], dev[16], name[256];
        unsigned long inode;
        name[0] = '\0';

        int n = sscanf(line, "%lx-%lx %7s %lx %15s %lu %255[^\n]",
                       &start, &end, perms, &file_off, dev, &inode, name);
        if (n < 6) continue;

        /* Skip zero-length regions */
        if (start == end) continue;

        map_entry_t *e = map_list_add(maps);
        if (!e) { fclose(f); return -1; }

        e->start       = start;
        e->end         = end;
        e->file_offset = file_off;

        /* Trim leading space from name */
        char *np = name;
        while (*np == ' ') np++;
        strlcpy(e->name, np, sizeof(e->name));

        e->flags = 0;
        if (perms[0] == 'r') e->flags |= PF_R;
        if (perms[1] == 'w') e->flags |= PF_W;
        if (perms[2] == 'x') e->flags |= PF_X;
    }
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */
/* ELF note construction                                               */

/*
 * Append a note to a growable buffer.
 * name is null-terminated; namesz = strlen(name)+1.
 * Both name and desc are padded to 4-byte boundaries in the output.
 */
static int append_note(uint8_t **buf, size_t *buf_sz, size_t *buf_cap,
                       uint32_t type, const char *name,
                       const void *desc, uint32_t descsz)
{
    uint32_t namesz  = (uint32_t)strlen(name) + 1;
    uint32_t name_pad = (namesz + 3) & ~3u;
    uint32_t desc_pad = (descsz + 3) & ~3u;
    size_t   need     = 12 + name_pad + desc_pad;

    if (*buf_sz + need > *buf_cap) {
        size_t nc = (*buf_cap ? *buf_cap : 4096);
        while (nc < *buf_sz + need) nc *= 2;
        uint8_t *p = realloc(*buf, nc);
        if (!p) { perror("realloc note buf"); return -1; }
        *buf     = p;
        *buf_cap = nc;
    }

    uint8_t *p = *buf + *buf_sz;
    uint32_t hdr[3] = { namesz, descsz, type };
    memcpy(p, hdr, 12);            p += 12;
    memset(p, 0, name_pad);
    memcpy(p, name, namesz);       p += name_pad;
    memset(p, 0, desc_pad);
    if (descsz) memcpy(p, desc, descsz);

    *buf_sz += need;
    return 0;
}

/* Build NT_PRSTATUS for one thread. */
static struct elf_prstatus make_prstatus(const thread_info_t *t, pid_t ppid)
{
    struct elf_prstatus ps;
    memset(&ps, 0, sizeof(ps));
    ps.pr_pid     = t->tid;
    ps.pr_ppid    = ppid;
    ps.pr_cursig  = SIGTRAP;
    ps.pr_info.si_signo = SIGTRAP;
    if (t->regs_valid)
        memcpy(&ps.pr_reg, &t->regs, sizeof(ps.pr_reg));
    return ps;
}

/* Build NT_PRPSINFO from /proc/<pid>/comm and /proc/<pid>/cmdline. */
static struct elf_prpsinfo make_prpsinfo(pid_t pid)
{
    struct elf_prpsinfo pi;
    memset(&pi, 0, sizeof(pi));
    pi.pr_pid   = pid;
    pi.pr_state = 0;
    pi.pr_sname = 'T';    /* Traced */

    /* comm: first 15 chars of executable name */
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
    FILE *f = fopen(path, "r");
    if (f) {
        char *_r __attribute__((unused)) = fgets(pi.pr_fname, sizeof(pi.pr_fname), f);
        /* strip trailing newline */
        char *nl = strchr(pi.pr_fname, '\n');
        if (nl) *nl = '\0';
        fclose(f);
    }

    /* cmdline: read and join with spaces */
    snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);
    f = fopen(path, "r");
    if (f) {
        size_t n = fread(pi.pr_psargs, 1, sizeof(pi.pr_psargs) - 1, f);
        fclose(f);
        /* cmdline args are NUL-separated; replace NULs with spaces */
        for (size_t i = 0; i < n; i++)
            if (pi.pr_psargs[i] == '\0') pi.pr_psargs[i] = ' ';
        if (n > 0) pi.pr_psargs[n - 1] = '\0';
    }

    return pi;
}

/*
 * Build NT_FILE note: maps each file-backed region to its filename.
 * Format: count, page_size, then (start, end, pgoff) * count, then filenames.
 */
static int append_nt_file(uint8_t **buf, size_t *sz, size_t *cap,
                          const map_list_t *maps)
{
    /* Count file-backed entries */
    int nf = 0;
    for (int i = 0; i < maps->count; i++)
        if (maps->data[i].name[0] == '/')
            nf++;

    size_t name_bytes = 0;
    for (int i = 0; i < maps->count; i++)
        if (maps->data[i].name[0] == '/')
            name_bytes += strlen(maps->data[i].name) + 1;

    size_t desc_sz = (size_t)(2 + 3 * nf) * sizeof(uint64_t) + name_bytes;
    uint8_t *desc  = calloc(1, desc_sz);
    if (!desc) return -1;

    uint64_t *wp = (uint64_t *)desc;
    *wp++ = (uint64_t)nf;
    *wp++ = (uint64_t)sysconf(_SC_PAGESIZE);

    for (int i = 0; i < maps->count; i++) {
        if (maps->data[i].name[0] != '/') continue;
        *wp++ = maps->data[i].start;
        *wp++ = maps->data[i].end;
        *wp++ = maps->data[i].file_offset / (uint64_t)sysconf(_SC_PAGESIZE);
    }

    char *sp = (char *)wp;
    for (int i = 0; i < maps->count; i++) {
        if (maps->data[i].name[0] != '/') continue;
        size_t l = strlen(maps->data[i].name) + 1;
        memcpy(sp, maps->data[i].name, l);
        sp += l;
    }

    int r = append_note(buf, sz, cap, NT_FILE, "CORE", desc, (uint32_t)desc_sz);
    free(desc);
    return r;
}

/* ------------------------------------------------------------------ */
/* Memory dumping from /proc/<pid>/mem                                 */

/*
 * Read a memory segment from /proc/<pid>/mem via pread, writing it to the
 * core file.  Unreadable pages are emitted as zeros.
 */
static int dump_segment(int core_fd, int mem_fd,
                        uint64_t vaddr, uint64_t size)
{
    char buf[65536];
    uint64_t off = 0;

    while (off < size) {
        size_t chunk = sizeof(buf);
        if (off + chunk > size) chunk = (size_t)(size - off);

        ssize_t r = pread(mem_fd, buf, chunk, (off_t)(vaddr + off));
        if (r <= 0) {
            /* Unreadable region - zero fill */
            memset(buf, 0, chunk);
            r = (ssize_t)chunk;
        }
        if (write_all(core_fd, buf, (size_t)r) < 0) return -1;
        off += (uint64_t)r;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Main dump entry point                                               */

int dump_core(qcore_state_t *state)
{
    pid_t cpid = state->child_pid;

    /* --- Parse /proc/child/maps --- */
    map_list_t maps = {0};
    if (parse_maps(cpid, &maps) < 0) return -1;
    printf("[phase5] %d memory region(s) found\n", maps.count);

    /* --- Build note section --- */
    uint8_t *notes    = NULL;
    size_t   notes_sz = 0;
    size_t   notes_cap= 0;

    /* NT_PRSTATUS for every parent thread (registers from Phase 1) */
    for (int i = 0; i < state->threads.count; i++) {
        struct elf_prstatus ps = make_prstatus(&state->threads.data[i],
                                               state->target_pid);
        if (append_note(&notes, &notes_sz, &notes_cap,
                        NT_PRSTATUS, "CORE", &ps, sizeof(ps)) < 0)
            return -1;
    }

    /* NT_PRPSINFO */
    struct elf_prpsinfo pi = make_prpsinfo(state->target_pid);
    if (append_note(&notes, &notes_sz, &notes_cap,
                    NT_PRPSINFO, "CORE", &pi, sizeof(pi)) < 0)
        return -1;

    /* NT_FILE */
    if (append_nt_file(&notes, &notes_sz, &notes_cap, &maps) < 0)
        return -1;

    /* --- Calculate file offsets --- */
    int n_load   = maps.count;
    int n_phdrs  = 1 + n_load;         /* PT_NOTE + PT_LOADs */

    uint64_t phdrs_end   = (uint64_t)(sizeof(Elf64_Ehdr) +
                                       (size_t)n_phdrs * sizeof(Elf64_Phdr));
    uint64_t notes_off   = phdrs_end;  /* notes immediately follow phdrs */
    uint64_t page_sz     = (uint64_t)sysconf(_SC_PAGESIZE);
    uint64_t data_start  = align_up(notes_off + notes_sz, page_sz);

    /* Compute per-segment file offsets */
    uint64_t *seg_off = calloc((size_t)n_load, sizeof(uint64_t));
    if (!seg_off) { perror("calloc seg_off"); return -1; }

    uint64_t cur_off = data_start;
    for (int i = 0; i < n_load; i++) {
        seg_off[i] = cur_off;
        /* Only readable segments contribute bytes to the file. */
        if (maps.data[i].flags & PF_R)
            cur_off += maps.data[i].end - maps.data[i].start;
        /* Page-align between segments for GDB mmap convenience */
        cur_off = align_up(cur_off, page_sz);
    }

    /* --- Open output file --- */
    int core_fd = open(state->core_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (core_fd < 0) {
        fprintf(stderr, "open(%s): %s\n", state->core_path, strerror(errno));
        free(seg_off); free(notes); free(maps.data);
        return -1;
    }

    /* --- Write ELF header --- */
    Elf64_Ehdr ehdr;
    memset(&ehdr, 0, sizeof(ehdr));
    ehdr.e_ident[EI_MAG0]    = ELFMAG0;
    ehdr.e_ident[EI_MAG1]    = ELFMAG1;
    ehdr.e_ident[EI_MAG2]    = ELFMAG2;
    ehdr.e_ident[EI_MAG3]    = ELFMAG3;
    ehdr.e_ident[EI_CLASS]   = ELFCLASS64;
    ehdr.e_ident[EI_DATA]    = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_ident[EI_OSABI]   = ELFOSABI_NONE;
    ehdr.e_type               = ET_CORE;
    ehdr.e_machine            = EM_X86_64;
    ehdr.e_version            = EV_CURRENT;
    ehdr.e_phoff              = sizeof(Elf64_Ehdr);
    ehdr.e_ehsize             = sizeof(Elf64_Ehdr);
    ehdr.e_phentsize          = sizeof(Elf64_Phdr);
    ehdr.e_phnum              = (Elf64_Half)n_phdrs;
    if (write_all(core_fd, &ehdr, sizeof(ehdr)) < 0) goto fail;

    /* --- Write PT_NOTE phdr --- */
    {
        Elf64_Phdr ph;
        memset(&ph, 0, sizeof(ph));
        ph.p_type    = PT_NOTE;
        ph.p_offset  = notes_off;
        ph.p_filesz  = (Elf64_Xword)notes_sz;
        ph.p_memsz   = (Elf64_Xword)notes_sz;
        ph.p_align   = 1;
        if (write_all(core_fd, &ph, sizeof(ph)) < 0) goto fail;
    }

    /* --- Write PT_LOAD phdrs --- */
    for (int i = 0; i < n_load; i++) {
        map_entry_t *m = &maps.data[i];
        uint64_t seg_sz = m->end - m->start;
        Elf64_Phdr ph;
        memset(&ph, 0, sizeof(ph));
        ph.p_type    = PT_LOAD;
        ph.p_flags   = (Elf64_Word)m->flags;
        ph.p_offset  = seg_off[i];
        ph.p_vaddr   = (Elf64_Addr)m->start;
        ph.p_paddr   = 0;
        ph.p_filesz  = (m->flags & PF_R) ? (Elf64_Xword)seg_sz : 0;
        ph.p_memsz   = (Elf64_Xword)seg_sz;
        ph.p_align   = page_sz;
        if (write_all(core_fd, &ph, sizeof(ph)) < 0) goto fail;
    }

    /* --- Write notes data --- */
    if (write_all(core_fd, notes, notes_sz) < 0) goto fail;

    /* --- Pad to data_start --- */
    {
        uint64_t cur = notes_off + notes_sz;
        if (write_zeros(core_fd, (size_t)(data_start - cur)) < 0) goto fail;
    }

    /* --- Open /proc/child/mem for reading --- */
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", (int)cpid);
    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        fprintf(stderr, "open(%s): %s\n", mem_path, strerror(errno));
        goto fail;
    }

    /* --- Dump each readable segment --- */
    for (int i = 0; i < n_load; i++) {
        map_entry_t *m = &maps.data[i];
        uint64_t seg_sz = m->end - m->start;

        if (!(m->flags & PF_R)) {
            /* Non-readable: advance file position with pad (p_filesz == 0) */
            if (write_zeros(core_fd, (size_t)(seg_off[i] - /* cur */ (i == 0
                    ? data_start : seg_off[i-1] + ((maps.data[i-1].flags & PF_R)
                    ? (maps.data[i-1].end - maps.data[i-1].start) : 0)))) < 0)
                goto fail_mem;
            continue;
        }

        /* Seek to segment file offset (handles gaps between segments) */
        if (lseek(core_fd, (off_t)seg_off[i], SEEK_SET) == -1) {
            perror("lseek core");
            goto fail_mem;
        }

        if (dump_segment(core_fd, mem_fd, m->start, seg_sz) < 0)
            goto fail_mem;

        /* Page-align for next segment */
        uint64_t end_off = seg_off[i] + seg_sz;
        uint64_t pad     = align_up(end_off, page_sz) - end_off;
        if (pad && write_zeros(core_fd, (size_t)pad) < 0) goto fail_mem;
    }

    close(mem_fd);
    close(core_fd);
    free(seg_off); free(notes); free(maps.data);
    printf("[phase5] core written to %s\n", state->core_path);
    return 0;

fail_mem:
    close(mem_fd);
fail:
    close(core_fd);
    free(seg_off); free(notes); free(maps.data);
    return -1;
}
