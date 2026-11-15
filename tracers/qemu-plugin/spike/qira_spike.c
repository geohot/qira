/*
 * SPIKE (Task 3, tracer assessment) -- not the real tracer.
 *
 * A minimal QEMU TCG plugin that writes QIRA's 24-byte change log with only
 * I (instruction start) and S (memory store) records. Like the legacy tracer
 * without -tracelibraries, only the main binary's instructions get a clnum, but
 * stores from all code (libraries, loader) are recorded at the current clnum.
 *
 * Written against the plugin API version 7 (QEMU 11.x: callbacks take a userdata
 * argument; older releases use different callback signatures).
 *
 * Build:
 *   gcc -shared -fPIC -O2 $(pkg-config --cflags glib-2.0) -I <qemu>/include/plugins \
 *       -o libqira_spike.so qira_spike.c
 * Run:
 *   qemu-x86_64 -plugin ./libqira_spike.so,out=/tmp/qira_logs/0 qira_tests/bin/loop
 */
#include <glib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* middleware/qira_log.py, Trace.h */
struct change {
    uint64_t address;
    uint64_t data;
    uint32_t clnum;
    uint32_t flags;
};
struct logstate {
    uint32_t change_count;
    uint32_t changelist_number;
    uint32_t is_filtered;
    uint32_t first_changelist_number;
    int32_t parent_id;
    int32_t this_pid;
};
#define IS_VALID 0x80000000u
#define IS_WRITE 0x40000000u
#define IS_MEM   0x20000000u
#define IS_START 0x10000000u

struct insn_info {
    uint64_t pc;
    uint32_t size;
};

static FILE *out;
static uint64_t text_lo, text_hi;
static uint32_t clnum; /* 0: loader/libc start-up; the first main-binary instruction is 1 */
static uint32_t count; /* records written, header excluded */

static void emit(uint64_t addr, uint64_t data, uint32_t flags)
{
    struct change c = { addr, data, clnum, flags };
    fwrite(&c, sizeof(c), 1, out);
    count++;
}

static void insn_exec(unsigned int vcpu, void *udata)
{
    struct insn_info *ii = udata;
    clnum++;
    emit(ii->pc, ii->size, IS_VALID | IS_START);
}

static void mem_access(unsigned int vcpu, qemu_plugin_meminfo_t info,
                       uint64_t vaddr, void *udata)
{
    if (!qemu_plugin_mem_is_store(info)) {
        return;
    }
    unsigned bytes = 1u << qemu_plugin_mem_size_shift(info);
    qemu_plugin_mem_value v = qemu_plugin_mem_get_value(info);
    uint64_t data;
    switch (v.type) {
    case QEMU_PLUGIN_MEM_VALUE_U8:  data = v.data.u8;  break;
    case QEMU_PLUGIN_MEM_VALUE_U16: data = v.data.u16; break;
    case QEMU_PLUGIN_MEM_VALUE_U32: data = v.data.u32; break;
    case QEMU_PLUGIN_MEM_VALUE_U64: data = v.data.u64; break;
    default:                        data = v.data.u128.low; break; /* spike: low half only */
    }
    emit(vaddr, data, IS_VALID | IS_WRITE | IS_MEM | (bytes * 8));
}

static void tb_trans(struct qemu_plugin_tb *tb, void *udata)
{
    if (text_hi == 0) {
        /* not available in qemu_plugin_install: the guest binary is loaded later */
        text_lo = qemu_plugin_start_code();
        text_hi = qemu_plugin_end_code();
    }
    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t pc = qemu_plugin_insn_vaddr(insn);
        qemu_plugin_register_vcpu_mem_cb(insn, mem_access, QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_W, NULL);
        if (pc < text_lo || pc >= text_hi) {
            continue; /* libraries and the loader get no clnum, as in the legacy tracer */
        }
        struct insn_info *ii = g_new(struct insn_info, 1); /* spike: never freed */
        ii->pc = pc;
        ii->size = qemu_plugin_insn_size(insn);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, insn_exec, QEMU_PLUGIN_CB_NO_REGS, ii);
    }
}

static int list_regs;

static void vcpu_init(unsigned int vcpu, void *udata)
{
    if (!list_regs) {
        return;
    }
    /* which registers the plugin API exposes, to map them to middleware/arch.py */
    GArray *regs = qemu_plugin_get_registers();
    for (guint i = 0; i < regs->len; i++) {
        qemu_plugin_reg_descriptor *rd = &g_array_index(regs, qemu_plugin_reg_descriptor, i);
        fprintf(stderr, "reg %u %s %s\n", i, rd->name, rd->feature ? rd->feature : "");
    }
    g_array_free(regs, TRUE);
}

static void at_exit(void *udata)
{
    struct logstate hdr = {
        .change_count = count + 1, /* the reader counts the header record */
        .changelist_number = clnum,
        .is_filtered = 0,
        .first_changelist_number = 0,
        .parent_id = -1,
        .this_pid = getpid(),
    };
    fseek(out, 0, SEEK_SET);
    fwrite(&hdr, sizeof(hdr), 1, out);
    fclose(out);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                           int argc, char **argv)
{
    const char *path = "/tmp/qira_logs/0";
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "out=", 4) == 0) {
            path = argv[i] + 4;
        } else if (strcmp(argv[i], "regs=on") == 0) {
            list_regs = 1;
        }
    }
    out = fopen(path, "wb");
    if (!out) {
        perror(path);
        return -1;
    }
    struct change zero = { 0 };
    fwrite(&zero, sizeof(zero), 1, out); /* header, filled in at exit */

    qemu_plugin_register_vcpu_init_cb(id, vcpu_init, NULL);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans, NULL);
    qemu_plugin_register_atexit_cb(id, at_exit, NULL);
    return 0;
}
