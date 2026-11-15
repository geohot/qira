/*
 * libqira.so -- QIRA tracer as a QEMU TCG plugin (Task 5, x86_64).
 *
 * Loads into unmodified upstream QEMU user-mode (`qemu-<arch> -plugin`), pinned to
 * QEMU 11.1.x / plugin API 7 (docs/tracer-assessment.md). Writes QIRA's legacy trace
 * format so the existing middleware and web UI work unchanged:
 *
 *   <dir>/<run>        24-byte change log  (middleware/qira_log.py, qiradb)
 *   <dir>/<id>_strace  "<clnum> <pid> name(args) = ret"
 *   <dir>/<id>_base    "<start>-<end> <file_offset_hex> <host_path>"  (main binary)
 *   <asm>              "<pc_hex>:  <disassembly>"   (shared asm file)
 *
 * Scope of this version: x86_64 Linux. Records I (instruction start), L/S (memory
 * load/store with values) and W (register writes, by diffing). No R (register reads:
 * the plugin API cannot observe them) and no fork/replay. See the Task 5 report for
 * the differences from the legacy tracer that remain.
 *
 * Build: make -C tracers/qemu-plugin   (needs glib-2.0 and qemu-plugin.h; the devenv
 * shell provides both, QEMU_PLUGIN_INCLUDE points at the header).
 */
#include <elf.h>
#include <glib.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#if QEMU_PLUGIN_VERSION != 7
#warning "built against a plugin API other than 7 (QEMU 11.1.x); check callback signatures"
#endif

/* --- QIRA log format (middleware/qira_log.py, qiradb Trace.h) --- */
struct change {
    uint64_t address;
    uint64_t data;
    uint32_t clnum;
    uint32_t flags;
};
struct logstate {               /* record 0 of the log */
    uint32_t change_count;
    uint32_t changelist_number;
    uint32_t is_filtered;
    uint32_t first_changelist_number;
    int32_t  parent_id;
    int32_t  this_pid;
};
#define IS_VALID   0x80000000u
#define IS_WRITE   0x40000000u
#define IS_MEM     0x20000000u
#define IS_START   0x10000000u
#define IS_SYSCALL 0x08000000u

/* x86_64 register layout the middleware expects: address = index * 8
 * (middleware/arch.py X64REGS). Mapping from the plugin API's gdb register names. */
static const char *const X64_BY_INDEX[] = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip",
};
#define N_X64REGS (int)(sizeof(X64_BY_INDEX) / sizeof(X64_BY_INDEX[0]))
#define REGSIZE 8

/* --- state --- */
static FILE *logf;
static FILE *stracef;
static FILE *asmf;
static int   pid;
static char  g_dir[PATH_MAX];
static int   g_id;
static int   trace_libs;
static uint64_t gate;           /* if set, do not trace until this pc is hit */
static int   gate_open = 1;

static uint64_t text_lo, text_hi;   /* main binary text, for filtering */
static uint32_t clnum;              /* 0 = start-up; first main-binary insn is 1 */
static uint32_t count;              /* change records written (header excluded) */

/* registers of interest: plugin handle -> X64REGS index */
static struct { struct qemu_plugin_register *h; int idx; } regs[N_X64REGS];
static int   n_regs;
static uint64_t prev_reg[N_X64REGS];   /* last seen value per X64REGS index */
static int   regs_inited;
static GByteArray *reg_buf;            /* scratch for read_register */

/* asm dedup: emit each pc's disassembly once */
static GHashTable *asm_seen;

/* strace fd -> path, for the middleware's mmap handling */
static GHashTable *fd_path;
/* syscall being processed (entry -> ret), x86_64 is single-vCPU here */
static int64_t sc_num, sc_a[6];

static void write_base(const char *dir, int id);

static void emit(uint64_t addr, uint64_t data, uint32_t flags)
{
    struct change c = { addr, data, clnum, flags };
    fwrite(&c, sizeof(c), 1, logf);
    count++;
}

static int in_text(uint64_t pc)
{
    return pc >= text_lo && pc < text_hi;
}

/* read the 17 tracked registers, emit W for any that changed (attributed to the
 * current clnum, i.e. the instruction that just finished). */
static void diff_registers(void)
{
    for (int i = 0; i < n_regs; i++) {
        g_byte_array_set_size(reg_buf, 0);
        if (!qemu_plugin_read_register(regs[i].h, reg_buf) || reg_buf->len == 0) {
            continue;
        }
        uint64_t v = 0;
        memcpy(&v, reg_buf->data, reg_buf->len < REGSIZE ? reg_buf->len : REGSIZE);
        int idx = regs[i].idx;
        if (!regs_inited || v != prev_reg[idx]) {
            emit((uint64_t)idx * REGSIZE, v, IS_VALID | IS_WRITE | (REGSIZE * 8));
            prev_reg[idx] = v;
        }
    }
    regs_inited = 1;
}

struct insn_info { uint64_t pc; uint32_t size; };

static void insn_exec(unsigned int vcpu, void *udata)
{
    struct insn_info *ii = udata;
    uint64_t pc = ii->pc;

    if (gate && gate_open == 0) {
        if (pc != gate) {
            return;
        }
        gate_open = 1;          /* reached the gate; start tracing here */
    }

    /* register writes of the previous instruction become visible now */
    diff_registers();
    clnum++;
    emit(pc, ii->size, IS_VALID | IS_START);
}

static void mem_cb(unsigned int vcpu, qemu_plugin_meminfo_t info,
                   uint64_t vaddr, void *udata)
{
    if (gate && !gate_open) {
        return;
    }
    unsigned bytes = 1u << qemu_plugin_mem_size_shift(info);
    qemu_plugin_mem_value v = qemu_plugin_mem_get_value(info);
    uint64_t data = 0;
    switch (v.type) {
    case QEMU_PLUGIN_MEM_VALUE_U8:   data = v.data.u8;  break;
    case QEMU_PLUGIN_MEM_VALUE_U16:  data = v.data.u16; break;
    case QEMU_PLUGIN_MEM_VALUE_U32:  data = v.data.u32; break;
    case QEMU_PLUGIN_MEM_VALUE_U64:  data = v.data.u64; break;
    case QEMU_PLUGIN_MEM_VALUE_U128: data = v.data.u128.low; break; /* low half */
    }
    uint32_t flags = IS_VALID | IS_MEM | (bytes * 8);
    if (qemu_plugin_mem_is_store(info)) {
        flags |= IS_WRITE;
    }
    emit(vaddr, data, flags);
}

static void write_asm(struct qemu_plugin_insn *insn, uint64_t pc)
{
    if (g_hash_table_contains(asm_seen, GUINT_TO_POINTER(pc))) {
        return;
    }
    g_hash_table_add(asm_seen, GUINT_TO_POINTER(pc));
    char *d = qemu_plugin_insn_disas(insn);
    /* "<pc>:  <insn>" — read_asm_file splits on ':' and takes the text after it.
     * Skip when QEMU has no disassembler (nixpkgs qemu-user is built without
     * capstone, so insn_disas is empty); static2/capstone disassembles from the
     * bytes loaded via _base instead. */
    if (d && d[0]) {
        fprintf(asmf, "%" PRIx64 ":  %s\n", pc, d);
    }
    g_free(d);
}

static void tb_trans(struct qemu_plugin_tb *tb, void *udata)
{
    if (text_hi == 0) {
        /* the guest binary is loaded after qemu_plugin_install, so query here */
        text_lo = qemu_plugin_start_code();
        text_hi = qemu_plugin_end_code();
        write_base(g_dir, g_id);
    }
    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t pc = qemu_plugin_insn_vaddr(insn);

        /* stores/loads from all code are recorded at the current clnum */
        qemu_plugin_register_vcpu_mem_cb(insn, mem_cb, QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW, NULL);

        if (!trace_libs && !in_text(pc)) {
            continue;   /* libraries/loader get no clnum, as in the legacy tracer */
        }
        write_asm(insn, pc);
        struct insn_info *ii = g_new(struct insn_info, 1);
        ii->pc = pc;
        ii->size = (uint32_t)qemu_plugin_insn_size(insn);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, insn_exec, QEMU_PLUGIN_CB_R_REGS, ii);
    }
}

/* ---- strace ---- */
static void strace_line(const char *text, int64_t ret)
{
    /* "<clnum> <pid> <text> = <ret>" */
    fprintf(stracef, "%u %d %s = %ld\n", clnum, pid, text, (long)ret);
    fflush(stracef);
}

/* x86_64 syscall numbers we format specially so the middleware can load mmap'd files */
#define NR_read 0
#define NR_open 2
#define NR_close 3
#define NR_mmap 9
#define NR_openat 257

static void vcpu_syscall(unsigned int vcpu, int64_t num,
                         uint64_t a1, uint64_t a2, uint64_t a3,
                         uint64_t a4, uint64_t a5, uint64_t a6,
                         uint64_t a7, uint64_t a8, void *udata)
{
    sc_num = num;
    sc_a[0] = a1; sc_a[1] = a2; sc_a[2] = a3;
    sc_a[3] = a4; sc_a[4] = a5; sc_a[5] = a6;
}

/* read a NUL-terminated guest string (for open/openat path arguments) */
static void guest_cstr(uint64_t gaddr, char *out, size_t max)
{
    GByteArray *b = g_byte_array_new();
    size_t i = 0;
    for (; i < max - 1; i++) {
        g_byte_array_set_size(b, 0);
        if (!qemu_plugin_read_memory_vaddr(gaddr + i, b, 1) || b->len < 1 || b->data[0] == 0) {
            break;
        }
        out[i] = (char)b->data[0];
    }
    out[i] = 0;
    g_byte_array_free(b, TRUE);
}

static void vcpu_syscall_ret(unsigned int vcpu, int64_t num, int64_t ret, void *udata)
{
    char buf[1100];

    if (num == NR_openat && (int64_t)ret >= 0) {
        char path[1024];
        guest_cstr(sc_a[1], path, sizeof(path));
        g_hash_table_insert(fd_path, GINT_TO_POINTER((int)ret), g_strdup(path));
        snprintf(buf, sizeof(buf), "openat(%ld,\"%s\",0x%lx)",
                 (long)(int64_t)sc_a[0], path, (unsigned long)sc_a[2]);
        strace_line(buf, ret);
    } else if (num == NR_open && (int64_t)ret >= 0) {
        char path[1024];
        guest_cstr(sc_a[0], path, sizeof(path));
        g_hash_table_insert(fd_path, GINT_TO_POINTER((int)ret), g_strdup(path));
        snprintf(buf, sizeof(buf), "open(\"%s\",0x%lx)", path, (unsigned long)sc_a[1]);
        strace_line(buf, ret);
    } else if (num == NR_mmap) {
        /* mmap(addr,size,prot,flags,fd,offset) — the middleware reads size, fd, offset */
        snprintf(buf, sizeof(buf), "mmap(0x%lx,0x%lx,0x%lx,0x%lx,%ld,0x%lx)",
                 (unsigned long)sc_a[0], (unsigned long)sc_a[1], (unsigned long)sc_a[2],
                 (unsigned long)sc_a[3], (long)(int64_t)sc_a[4], (unsigned long)sc_a[5]);
        strace_line(buf, ret);
    } else {
        snprintf(buf, sizeof(buf), "syscall_%ld(0x%lx,0x%lx,0x%lx)",
                 (long)num, (unsigned long)sc_a[0], (unsigned long)sc_a[1],
                 (unsigned long)sc_a[2]);
        strace_line(buf, ret);
    }
}

/* ---- register discovery ---- */
static void vcpu_init(unsigned int vcpu, void *udata)
{
    if (n_regs) {
        return;
    }
    GArray *descs = qemu_plugin_get_registers();
    for (guint i = 0; descs && i < descs->len; i++) {
        qemu_plugin_reg_descriptor *rd =
            &g_array_index(descs, qemu_plugin_reg_descriptor, i);
        for (int k = 0; k < N_X64REGS; k++) {
            if (g_strcmp0(rd->name, X64_BY_INDEX[k]) == 0) {
                regs[n_regs].h = rd->handle;
                regs[n_regs].idx = k;
                n_regs++;
                break;
            }
        }
    }
    if (descs) {
        g_array_free(descs, TRUE);
    }
}

/* ---- main binary _base, from its ELF program headers ---- */
static void write_base(const char *dir, int id)
{
    const char *path = qemu_plugin_path_to_binary();
    if (!path) {
        return;
    }
    FILE *bin = fopen(path, "rb");
    if (!bin) {
        return;
    }
    Elf64_Ehdr eh;
    if (fread(&eh, sizeof(eh), 1, bin) != 1 ||
        memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64) {
        fclose(bin);
        return;
    }
    char *bp = realpath(path, NULL);
    char fn[PATH_MAX];
    snprintf(fn, sizeof(fn), "%s/%d_base", dir, id);
    FILE *f = fopen(fn, "w");
    if (f) {
        for (int i = 0; i < eh.e_phnum; i++) {
            Elf64_Phdr ph;
            if (fseek(bin, eh.e_phoff + (long)i * eh.e_phentsize, SEEK_SET) != 0 ||
                fread(&ph, sizeof(ph), 1, bin) != 1) {
                break;
            }
            if (ph.p_type != PT_LOAD || ph.p_filesz == 0) {
                continue;
            }
            /* <vaddr>-<vaddr+filesz> <file_offset> <path> : the middleware seeks to
             * offset in the file, reads (end-start) bytes, maps them at start. */
            fprintf(f, "%" PRIx64 "-%" PRIx64 " %" PRIx64 " %s\n",
                    (uint64_t)ph.p_vaddr, (uint64_t)(ph.p_vaddr + ph.p_filesz),
                    (uint64_t)ph.p_offset, bp ? bp : path);
        }
        fclose(f);
    }
    free(bp);
    fclose(bin);
}

/* ---- lifecycle ---- */
static void at_exit(void *udata)
{
    struct logstate hdr = {
        .change_count = count + 1,          /* the reader counts the header record */
        .changelist_number = clnum,
        .is_filtered = 0,
        .first_changelist_number = 0,
        .parent_id = -1,
        .this_pid = pid,
    };
    fseek(logf, 0, SEEK_SET);
    fwrite(&hdr, sizeof(hdr), 1, logf);
    fclose(logf);
    if (stracef) fclose(stracef);
    if (asmf) fclose(asmf);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                           int argc, char **argv)
{
    const char *dir = "/tmp/qira_logs";
    const char *asm_path = "/tmp/qira_asm";
    g_id = 0;

    for (int i = 0; i < argc; i++) {
        if (g_str_has_prefix(argv[i], "dir=")) {
            dir = argv[i] + 4;
        } else if (g_str_has_prefix(argv[i], "run=")) {
            g_id = atoi(argv[i] + 4);
        } else if (g_str_has_prefix(argv[i], "asm=")) {
            asm_path = argv[i] + 4;
        } else if (g_strcmp0(argv[i], "tracelibs=on") == 0) {
            trace_libs = 1;
        } else if (g_str_has_prefix(argv[i], "gate=")) {
            gate = strtoull(argv[i] + 5, NULL, 0);
            gate_open = 0;
        }
    }
    if (g_strcmp0(info->target_name, "x86_64") != 0) {
        fprintf(stderr, "libqira: only x86_64 is supported in this version (got %s)\n",
                info->target_name);
        return -1;
    }

    pid = getpid();
    snprintf(g_dir, sizeof(g_dir), "%s", dir);

    char fn[PATH_MAX];
    snprintf(fn, sizeof(fn), "%s/%d", dir, g_id);
    unlink(fn);
    logf = fopen(fn, "wb");
    if (!logf) {
        perror(fn);
        return -1;
    }
    struct change zero = { 0 };
    fwrite(&zero, sizeof(zero), 1, logf);   /* header, filled in at_exit */

    snprintf(fn, sizeof(fn), "%s/%d_strace", dir, g_id);
    stracef = fopen(fn, "w");
    asmf = fopen(asm_path, "a");             /* shared asm file, append like the legacy */

    reg_buf = g_byte_array_new();
    asm_seen = g_hash_table_new(g_direct_hash, g_direct_equal);
    fd_path = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

    qemu_plugin_register_vcpu_init_cb(id, vcpu_init, NULL);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans, NULL);
    qemu_plugin_register_vcpu_syscall_cb(id, vcpu_syscall, NULL);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, vcpu_syscall_ret, NULL);
    qemu_plugin_register_atexit_cb(id, at_exit, NULL);
    return 0;
}
