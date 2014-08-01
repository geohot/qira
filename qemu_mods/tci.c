/*
 * Tiny Code Interpreter for QEMU
 *
 * Copyright (c) 2009, 2011 Stefan Weil
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

/* Defining NDEBUG disables assertions (which makes the code faster). */
#if !defined(CONFIG_DEBUG_TCG) && !defined(NDEBUG)
# define NDEBUG
#endif

#include "qemu-common.h"
#include "exec/exec-all.h"           /* MAX_OPC_PARAM_IARGS */
#include "exec/cpu_ldst.h"
#include "tcg-op.h"

/* Marker for missing code. */
#define TODO() \
    do { \
        fprintf(stderr, "TODO %s:%u: %s()\n", \
                __FILE__, __LINE__, __func__); \
        tcg_abort(); \
    } while (0)

#if MAX_OPC_PARAM_IARGS != 5
# error Fix needed, number of supported input arguments changed!
#endif
#if TCG_TARGET_REG_BITS == 32
typedef uint64_t (*helper_function)(tcg_target_ulong, tcg_target_ulong,
                                    tcg_target_ulong, tcg_target_ulong,
                                    tcg_target_ulong, tcg_target_ulong,
                                    tcg_target_ulong, tcg_target_ulong,
                                    tcg_target_ulong, tcg_target_ulong);
#else
typedef uint64_t (*helper_function)(tcg_target_ulong, tcg_target_ulong,
                                    tcg_target_ulong, tcg_target_ulong,
                                    tcg_target_ulong);
#endif

/* Targets which don't use GETPC also don't need tci_tb_ptr
   which makes them a little faster. */
#if defined(GETPC)
uintptr_t tci_tb_ptr;
#endif

static tcg_target_ulong tci_reg[TCG_TARGET_NB_REGS];

static tcg_target_ulong tci_read_reg(TCGReg index)
{
    assert(index < ARRAY_SIZE(tci_reg));
    return tci_reg[index];
}

#if TCG_TARGET_HAS_ext8s_i32 || TCG_TARGET_HAS_ext8s_i64
static int8_t tci_read_reg8s(TCGReg index)
{
    return (int8_t)tci_read_reg(index);
}
#endif

#if TCG_TARGET_HAS_ext16s_i32 || TCG_TARGET_HAS_ext16s_i64
static int16_t tci_read_reg16s(TCGReg index)
{
    return (int16_t)tci_read_reg(index);
}
#endif

#if TCG_TARGET_REG_BITS == 64
static int32_t tci_read_reg32s(TCGReg index)
{
    return (int32_t)tci_read_reg(index);
}
#endif

static uint8_t tci_read_reg8(TCGReg index)
{
    return (uint8_t)tci_read_reg(index);
}

static uint16_t tci_read_reg16(TCGReg index)
{
    return (uint16_t)tci_read_reg(index);
}

static uint32_t tci_read_reg32(TCGReg index)
{
    return (uint32_t)tci_read_reg(index);
}

#if TCG_TARGET_REG_BITS == 64
static uint64_t tci_read_reg64(TCGReg index)
{
    return tci_read_reg(index);
}
#endif

static void tci_write_reg(TCGReg index, tcg_target_ulong value)
{
    assert(index < ARRAY_SIZE(tci_reg));
    assert(index != TCG_AREG0);
    assert(index != TCG_REG_CALL_STACK);
    tci_reg[index] = value;
}

#if TCG_TARGET_REG_BITS == 64
static void tci_write_reg32s(TCGReg index, int32_t value)
{
    tci_write_reg(index, value);
}
#endif

static void tci_write_reg8(TCGReg index, uint8_t value)
{
    tci_write_reg(index, value);
}

static void tci_write_reg32(TCGReg index, uint32_t value)
{
    tci_write_reg(index, value);
}

#if TCG_TARGET_REG_BITS == 32
static void tci_write_reg64(uint32_t high_index, uint32_t low_index,
                            uint64_t value)
{
    tci_write_reg(low_index, value);
    tci_write_reg(high_index, value >> 32);
}
#elif TCG_TARGET_REG_BITS == 64
static void tci_write_reg64(TCGReg index, uint64_t value)
{
    tci_write_reg(index, value);
}
#endif

#if TCG_TARGET_REG_BITS == 32
/* Create a 64 bit value from two 32 bit values. */
static uint64_t tci_uint64(uint32_t high, uint32_t low)
{
    return ((uint64_t)high << 32) + low;
}
#endif

/* Read constant (native size) from bytecode. */
static tcg_target_ulong tci_read_i(uint8_t **tb_ptr)
{
    tcg_target_ulong value = *(tcg_target_ulong *)(*tb_ptr);
    *tb_ptr += sizeof(value);
    return value;
}

/* Read unsigned constant (32 bit) from bytecode. */
static uint32_t tci_read_i32(uint8_t **tb_ptr)
{
    uint32_t value = *(uint32_t *)(*tb_ptr);
    *tb_ptr += sizeof(value);
    return value;
}

/* Read signed constant (32 bit) from bytecode. */
static int32_t tci_read_s32(uint8_t **tb_ptr)
{
    int32_t value = *(int32_t *)(*tb_ptr);
    *tb_ptr += sizeof(value);
    return value;
}

#if TCG_TARGET_REG_BITS == 64
/* Read constant (64 bit) from bytecode. */
static uint64_t tci_read_i64(uint8_t **tb_ptr)
{
    uint64_t value = *(uint64_t *)(*tb_ptr);
    *tb_ptr += sizeof(value);
    return value;
}
#endif

/* Read indexed register (native size) from bytecode. */
static tcg_target_ulong tci_read_r(uint8_t **tb_ptr)
{
    tcg_target_ulong value = tci_read_reg(**tb_ptr);
    *tb_ptr += 1;
    return value;
}

/* Read indexed register (8 bit) from bytecode. */
static uint8_t tci_read_r8(uint8_t **tb_ptr)
{
    uint8_t value = tci_read_reg8(**tb_ptr);
    *tb_ptr += 1;
    return value;
}

#if TCG_TARGET_HAS_ext8s_i32 || TCG_TARGET_HAS_ext8s_i64
/* Read indexed register (8 bit signed) from bytecode. */
static int8_t tci_read_r8s(uint8_t **tb_ptr)
{
    int8_t value = tci_read_reg8s(**tb_ptr);
    *tb_ptr += 1;
    return value;
}
#endif

/* Read indexed register (16 bit) from bytecode. */
static uint16_t tci_read_r16(uint8_t **tb_ptr)
{
    uint16_t value = tci_read_reg16(**tb_ptr);
    *tb_ptr += 1;
    return value;
}

#if TCG_TARGET_HAS_ext16s_i32 || TCG_TARGET_HAS_ext16s_i64
/* Read indexed register (16 bit signed) from bytecode. */
static int16_t tci_read_r16s(uint8_t **tb_ptr)
{
    int16_t value = tci_read_reg16s(**tb_ptr);
    *tb_ptr += 1;
    return value;
}
#endif

/* Read indexed register (32 bit) from bytecode. */
static uint32_t tci_read_r32(uint8_t **tb_ptr)
{
    uint32_t value = tci_read_reg32(**tb_ptr);
    *tb_ptr += 1;
    return value;
}

#if TCG_TARGET_REG_BITS == 32
/* Read two indexed registers (2 * 32 bit) from bytecode. */
static uint64_t tci_read_r64(uint8_t **tb_ptr)
{
    uint32_t low = tci_read_r32(tb_ptr);
    return tci_uint64(tci_read_r32(tb_ptr), low);
}
#elif TCG_TARGET_REG_BITS == 64
/* Read indexed register (32 bit signed) from bytecode. */
static int32_t tci_read_r32s(uint8_t **tb_ptr)
{
    int32_t value = tci_read_reg32s(**tb_ptr);
    *tb_ptr += 1;
    return value;
}

/* Read indexed register (64 bit) from bytecode. */
static uint64_t tci_read_r64(uint8_t **tb_ptr)
{
    uint64_t value = tci_read_reg64(**tb_ptr);
    *tb_ptr += 1;
    return value;
}
#endif

/* Read indexed register(s) with target address from bytecode. */
static target_ulong tci_read_ulong(uint8_t **tb_ptr)
{
    target_ulong taddr = tci_read_r(tb_ptr);
#if TARGET_LONG_BITS > TCG_TARGET_REG_BITS
    taddr += (uint64_t)tci_read_r(tb_ptr) << 32;
#endif
    return taddr;
}

/* Read indexed register or constant (native size) from bytecode. */
static tcg_target_ulong tci_read_ri(uint8_t **tb_ptr)
{
    tcg_target_ulong value;
    TCGReg r = **tb_ptr;
    *tb_ptr += 1;
    if (r == TCG_CONST) {
        value = tci_read_i(tb_ptr);
    } else {
        value = tci_read_reg(r);
    }
    return value;
}

/* Read indexed register or constant (32 bit) from bytecode. */
static uint32_t tci_read_ri32(uint8_t **tb_ptr)
{
    uint32_t value;
    TCGReg r = **tb_ptr;
    *tb_ptr += 1;
    if (r == TCG_CONST) {
        value = tci_read_i32(tb_ptr);
    } else {
        value = tci_read_reg32(r);
    }
    return value;
}

#if TCG_TARGET_REG_BITS == 32
/* Read two indexed registers or constants (2 * 32 bit) from bytecode. */
static uint64_t tci_read_ri64(uint8_t **tb_ptr)
{
    uint32_t low = tci_read_ri32(tb_ptr);
    return tci_uint64(tci_read_ri32(tb_ptr), low);
}
#elif TCG_TARGET_REG_BITS == 64
/* Read indexed register or constant (64 bit) from bytecode. */
static uint64_t tci_read_ri64(uint8_t **tb_ptr)
{
    uint64_t value;
    TCGReg r = **tb_ptr;
    *tb_ptr += 1;
    if (r == TCG_CONST) {
        value = tci_read_i64(tb_ptr);
    } else {
        value = tci_read_reg64(r);
    }
    return value;
}
#endif

static tcg_target_ulong tci_read_label(uint8_t **tb_ptr)
{
    tcg_target_ulong label = tci_read_i(tb_ptr);
    assert(label != 0);
    return label;
}

static bool tci_compare32(uint32_t u0, uint32_t u1, TCGCond condition)
{
    bool result = false;
    int32_t i0 = u0;
    int32_t i1 = u1;
    switch (condition) {
    case TCG_COND_EQ:
        result = (u0 == u1);
        break;
    case TCG_COND_NE:
        result = (u0 != u1);
        break;
    case TCG_COND_LT:
        result = (i0 < i1);
        break;
    case TCG_COND_GE:
        result = (i0 >= i1);
        break;
    case TCG_COND_LE:
        result = (i0 <= i1);
        break;
    case TCG_COND_GT:
        result = (i0 > i1);
        break;
    case TCG_COND_LTU:
        result = (u0 < u1);
        break;
    case TCG_COND_GEU:
        result = (u0 >= u1);
        break;
    case TCG_COND_LEU:
        result = (u0 <= u1);
        break;
    case TCG_COND_GTU:
        result = (u0 > u1);
        break;
    default:
        TODO();
    }
    return result;
}

static bool tci_compare64(uint64_t u0, uint64_t u1, TCGCond condition)
{
    bool result = false;
    int64_t i0 = u0;
    int64_t i1 = u1;
    switch (condition) {
    case TCG_COND_EQ:
        result = (u0 == u1);
        break;
    case TCG_COND_NE:
        result = (u0 != u1);
        break;
    case TCG_COND_LT:
        result = (i0 < i1);
        break;
    case TCG_COND_GE:
        result = (i0 >= i1);
        break;
    case TCG_COND_LE:
        result = (i0 <= i1);
        break;
    case TCG_COND_GT:
        result = (i0 > i1);
        break;
    case TCG_COND_LTU:
        result = (u0 < u1);
        break;
    case TCG_COND_GEU:
        result = (u0 >= u1);
        break;
    case TCG_COND_LEU:
        result = (u0 <= u1);
        break;
    case TCG_COND_GTU:
        result = (u0 > u1);
        break;
    default:
        TODO();
    }
    return result;
}

// if it's not softmmu, assume it's user
#ifndef CONFIG_SOFTMMU
#define QEMU_USER
#endif

#define QIRA_TRACKING

#ifdef QIRA_TRACKING

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/file.h>

#ifdef QEMU_USER
#include "qemu.h"
#endif

#define QIRA_DEBUG(...) {}
//#define QIRA_DEBUG qemu_debug
//#define QIRA_DEBUG printf

// struct storing change data
struct change {
  uint64_t address;
  uint64_t data;
  uint32_t changelist_number;
  uint32_t flags;
};

// prototypes
void init_QIRA(CPUArchState *env, int id);
struct change *add_change(target_ulong addr, uint64_t data, uint32_t flags);
void track_load(target_ulong a, uint64_t data, int size);
void track_store(target_ulong a, uint64_t data, int size);
void track_read(target_ulong base, target_ulong offset, target_ulong data, int size);
void track_write(target_ulong base, target_ulong offset, target_ulong data, int size);
void add_pending_change(target_ulong addr, uint64_t data, uint32_t flags);
void commit_pending_changes(void);
void resize_change_buffer(size_t size);

// defined in qemu.h
//void track_kernel_read(void *host_addr, target_ulong guest_addr, long len);
//void track_kernel_write(void *host_addr, target_ulong guest_addr, long len);

#define IS_VALID      0x80000000
#define IS_WRITE      0x40000000
#define IS_MEM        0x20000000
#define IS_START      0x10000000
#define IS_SYSCALL    0x08000000
#define SIZE_MASK 0xFF

#define FAKE_SYSCALL_LOADSEG 0x10001

int GLOBAL_QIRA_did_init = 0;
CPUArchState *GLOBAL_CPUArchState;
struct change *GLOBAL_change_buffer;

uint32_t GLOBAL_qira_log_fd;
uint32_t GLOBAL_change_size;

// current state that must survive forks
struct logstate {
  uint32_t change_count;
  uint32_t changelist_number;
  uint32_t is_filtered;
  uint32_t first_changelist_number;
  int parent_id;
  int this_pid;
};
struct logstate *GLOBAL_logstate;

// input args
uint32_t GLOBAL_start_clnum = 1;
int GLOBAL_parent_id = -1, GLOBAL_id = -1;

int GLOBAL_tracelibraries = 0;

#define OPEN_GLOBAL_ASM_FILE { if (unlikely(GLOBAL_asm_file == NULL)) { GLOBAL_asm_file = fopen("/tmp/qira_asm", "a"); } }
FILE *GLOBAL_asm_file = NULL;
FILE *GLOBAL_strace_file = NULL;

// should be 0ed on startup
#define PENDING_CHANGES_MAX_ADDR 0x100
struct change GLOBAL_pending_changes[PENDING_CHANGES_MAX_ADDR/4];

uint32_t get_current_clnum(void);
uint32_t get_current_clnum(void) {
  return GLOBAL_logstate->changelist_number;
}

void resize_change_buffer(size_t size) {
  if(ftruncate(GLOBAL_qira_log_fd, size)) {
    perror("ftruncate");
  }
  GLOBAL_change_buffer = mmap(NULL, size,
         PROT_READ | PROT_WRITE, MAP_SHARED, GLOBAL_qira_log_fd, 0);
  GLOBAL_logstate = (struct logstate *)GLOBAL_change_buffer;
  if (GLOBAL_change_buffer == NULL) QIRA_DEBUG("MMAP FAILED!\n");
}

void init_QIRA(CPUArchState *env, int id) {
  QIRA_DEBUG("init QIRA called\n");
  GLOBAL_QIRA_did_init = 1;
  GLOBAL_CPUArchState = env;   // unused

  OPEN_GLOBAL_ASM_FILE

  char fn[PATH_MAX];
  sprintf(fn, "/tmp/qira_logs/%d_strace", id);
  GLOBAL_strace_file = fopen(fn, "w");

  sprintf(fn, "/tmp/qira_logs/%d", id);

  // unlink it first
  unlink(fn);
  GLOBAL_qira_log_fd = open(fn, O_RDWR | O_CREAT, 0644);
  GLOBAL_change_size = 1;
  memset(GLOBAL_pending_changes, 0, (PENDING_CHANGES_MAX_ADDR/4) * sizeof(struct change));

  resize_change_buffer(GLOBAL_change_size * sizeof(struct change));
  memset(GLOBAL_change_buffer, 0, sizeof(struct change));

  // skip the first change
  GLOBAL_logstate->change_count = 1;
  GLOBAL_logstate->is_filtered = 0;
  GLOBAL_logstate->this_pid = getpid();

  // do this after init_QIRA
  GLOBAL_logstate->changelist_number = GLOBAL_start_clnum-1;
  GLOBAL_logstate->first_changelist_number = GLOBAL_start_clnum;
  GLOBAL_logstate->parent_id = GLOBAL_parent_id;

  // use all fds up to 30
  int i;
  int dupme = open("/dev/null", O_RDONLY);
  struct stat useless;
  for (i = 0; i < 30; i++) {
    sprintf(fn, "/proc/self/fd/%d", i);
    if (stat(fn, &useless) == -1) {
      //printf("dup2 %d %d\n", dupme, i);
      dup2(dupme, i);
    }
  }

  // no more opens can happen here in QEMU, only the target process
}

struct change *add_change(target_ulong addr, uint64_t data, uint32_t flags) {
  int cc = __sync_fetch_and_add(&GLOBAL_logstate->change_count, 1);

  if (cc == GLOBAL_change_size) {
    // double the buffer size
    QIRA_DEBUG("doubling buffer with size %d\n", GLOBAL_change_size);
    resize_change_buffer(GLOBAL_change_size * sizeof(struct change) * 2);
    GLOBAL_change_size *= 2;
  }
  struct change *this_change = GLOBAL_change_buffer + cc;
  this_change->address = (uint64_t)addr;
  this_change->data = data;
  this_change->changelist_number = GLOBAL_logstate->changelist_number;
  this_change->flags = IS_VALID | flags;
  return this_change;
}

void add_pending_change(target_ulong addr, uint64_t data, uint32_t flags) {
  if (addr < PENDING_CHANGES_MAX_ADDR) {
    GLOBAL_pending_changes[addr/4].address = (uint64_t)addr;
    GLOBAL_pending_changes[addr/4].data = data;
    GLOBAL_pending_changes[addr/4].flags = IS_VALID | flags;
  }
}

void commit_pending_changes(void) {
  int i;
  for (i = 0; i < PENDING_CHANGES_MAX_ADDR/4; i++) {
    struct change *c = &GLOBAL_pending_changes[i];
    if (c->flags & IS_VALID) add_change(c->address, c->data, c->flags);
  }
  memset(GLOBAL_pending_changes, 0, (PENDING_CHANGES_MAX_ADDR/4) * sizeof(struct change));
}

struct change *track_syscall_begin(void *env, target_ulong sysnr);
struct change *track_syscall_begin(void *env, target_ulong sysnr) {
  int i;
  QIRA_DEBUG("syscall: %d\n", sysnr);
  if (GLOBAL_logstate->is_filtered == 1) {
    for (i = 0; i < 0x20; i+=4) {
      add_change(i, *(target_ulong*)(env+i), IS_WRITE | (sizeof(target_ulong)*8));
    }
  }
  return add_change(sysnr, 0, IS_SYSCALL);
}


// all loads and store happen in libraries...
void track_load(target_ulong addr, uint64_t data, int size) {
  QIRA_DEBUG("load:  0x%x:%d\n", addr, size);
  add_change(addr, data, IS_MEM | size);
}

void track_store(target_ulong addr, uint64_t data, int size) {
  QIRA_DEBUG("store: 0x%x:%d = 0x%lX\n", addr, size, data);
  add_change(addr, data, IS_MEM | IS_WRITE | size);
}

void track_read(target_ulong base, target_ulong offset, target_ulong data, int size) {
  QIRA_DEBUG("read:  %x+%x:%d = %x\n", base, offset, size, data);
  if ((int)offset < 0) return;
  if (GLOBAL_logstate->is_filtered == 0) add_change(offset, data, size);
}

void track_write(target_ulong base, target_ulong offset, target_ulong data, int size) {
  QIRA_DEBUG("write: %x+%x:%d = %x\n", base, offset, size, data);
  if ((int)offset < 0) return;
  if (GLOBAL_logstate->is_filtered == 0) add_change(offset, data, IS_WRITE | size);
  else add_pending_change(offset, data, IS_WRITE | size);
  //else add_change(offset, data, IS_WRITE | size);
}

#ifdef QEMU_USER

void track_kernel_read(void *host_addr, target_ulong guest_addr, long len) {
  if (unlikely(GLOBAL_QIRA_did_init == 0)) return;

  // this is generating tons of changes, and maybe not too useful
  /*QIRA_DEBUG("kernel_read: %p %X %ld\n", host_addr, guest_addr, len);
  long i = 0;
  //for (; i < len; i+=4) add_change(guest_addr+i, ((unsigned int*)host_addr)[i], IS_MEM | 32);
  for (; i < len; i+=1) add_change(guest_addr+i, ((unsigned char*)host_addr)[i], IS_MEM | 8);*/
}

void track_kernel_write(void *host_addr, target_ulong guest_addr, long len) {
  if (unlikely(GLOBAL_QIRA_did_init == 0)) return;
  // clamp at 0x40, badness
  //if (len > 0x40) len = 0x40;

  QIRA_DEBUG("kernel_write: %p %X %ld\n", host_addr, guest_addr, len);
  long i = 0;
  //for (; i < len; i+=4) add_change(guest_addr+i, ((unsigned int*)host_addr)[i], IS_MEM | IS_WRITE | 32);
  for (; i < len; i+=1) add_change(guest_addr+i, ((unsigned char*)host_addr)[i], IS_MEM | IS_WRITE | 8);
}

#endif

// careful, this does it twice, MMIO?
#define R(x,y,z) (track_load(x,(uint64_t)y,z),y)
#define W(x,y,z) (track_store(x,(uint64_t)y,z),x)

#else

#define R(x,y,z) y
#define W(x,y,z) x
#define track_read(x,y,z) ;
#define track_write(w,x,y,z) ;

#endif


#ifdef CONFIG_SOFTMMU
# define mmuidx          tci_read_i(&tb_ptr)
# define qemu_ld_ub \
    helper_ret_ldub_mmu(env, taddr, mmuidx, (uintptr_t)tb_ptr)
# define qemu_ld_leuw \
    helper_le_lduw_mmu(env, taddr, mmuidx, (uintptr_t)tb_ptr)
# define qemu_ld_leul \
    helper_le_ldul_mmu(env, taddr, mmuidx, (uintptr_t)tb_ptr)
# define qemu_ld_leq \
    helper_le_ldq_mmu(env, taddr, mmuidx, (uintptr_t)tb_ptr)
# define qemu_ld_beuw \
    helper_be_lduw_mmu(env, taddr, mmuidx, (uintptr_t)tb_ptr)
# define qemu_ld_beul \
    helper_be_ldul_mmu(env, taddr, mmuidx, (uintptr_t)tb_ptr)
# define qemu_ld_beq \
    helper_be_ldq_mmu(env, taddr, mmuidx, (uintptr_t)tb_ptr)
# define qemu_st_b(X) \
    helper_ret_stb_mmu(env, taddr, X, mmuidx, (uintptr_t)tb_ptr)
# define qemu_st_lew(X) \
    helper_le_stw_mmu(env, taddr, X, mmuidx, (uintptr_t)tb_ptr)
# define qemu_st_lel(X) \
    helper_le_stl_mmu(env, taddr, X, mmuidx, (uintptr_t)tb_ptr)
# define qemu_st_leq(X) \
    helper_le_stq_mmu(env, taddr, X, mmuidx, (uintptr_t)tb_ptr)
# define qemu_st_bew(X) \
    helper_be_stw_mmu(env, taddr, X, mmuidx, (uintptr_t)tb_ptr)
# define qemu_st_bel(X) \
    helper_be_stl_mmu(env, taddr, X, mmuidx, (uintptr_t)tb_ptr)
# define qemu_st_beq(X) \
    helper_be_stq_mmu(env, taddr, X, mmuidx, (uintptr_t)tb_ptr)
#else
# define qemu_ld_ub      R(taddr, ldub_p(g2h(taddr)), 8)
# define qemu_ld_leuw    R(taddr, lduw_le_p(g2h(taddr)), 16)
# define qemu_ld_leul    R(taddr, (uint32_t)ldl_le_p(g2h(taddr)), 32)
# define qemu_ld_leq     R(taddr, ldq_le_p(g2h(taddr)), 64)
# define qemu_ld_beuw    R(taddr, lduw_be_p(g2h(taddr)), 16)
# define qemu_ld_beul    R(taddr, (uint32_t)ldl_be_p(g2h(taddr)), 32)
# define qemu_ld_beq     R(taddr, ldq_be_p(g2h(taddr)), 64)
# define qemu_st_b(X)    stb_p(g2h(W(taddr,X,8)), X)
# define qemu_st_lew(X)  stw_le_p(g2h(W(taddr,X,16)), X)
# define qemu_st_lel(X)  stl_le_p(g2h(W(taddr,X,32)), X)
# define qemu_st_leq(X)  stq_le_p(g2h(W(taddr,X,64)), X)
# define qemu_st_bew(X)  stw_be_p(g2h(W(taddr,X,16)), X)
# define qemu_st_bel(X)  stl_be_p(g2h(W(taddr,X,32)), X)
# define qemu_st_beq(X)  stq_be_p(g2h(W(taddr,X,64)), X)
#endif

// poorly written, and it fills in holes
int get_next_id(void);
int get_next_id(void) {
  char fn[PATH_MAX];
  int this_id = 0;
  struct stat junk;
  while (1) {
    sprintf(fn, "/tmp/qira_logs/%d", this_id);
    if (stat(fn, &junk) == -1) break;
    this_id++;
  }
  return this_id;
}

int run_QIRA_log_from_fd(CPUArchState *env, int qira_log_fd, uint32_t to_change);
int run_QIRA_log_from_fd(CPUArchState *env, int qira_log_fd, uint32_t to_change) {
  struct change pchange;
  // skip the first change
  lseek(qira_log_fd, sizeof(pchange), SEEK_SET);
  int ret = 0;
  while(1) {
    if (read(qira_log_fd, &pchange, sizeof(pchange)) != sizeof(pchange)) { break; }
    uint32_t flags = pchange.flags;
    if (!(flags & IS_VALID)) break;
    if (pchange.changelist_number >= to_change) break;
    QIRA_DEBUG("running old change %lX %d\n", pchange.address, pchange.changelist_number);

#ifdef QEMU_USER
#ifdef R_EAX
    if (flags & IS_SYSCALL) {
      // replay all the syscalls?
      // skip reads
      if (pchange.address == FAKE_SYSCALL_LOADSEG) {
        //printf("LOAD_SEG!\n");
        helper_load_seg(env, pchange.data >> 32, pchange.data & 0xFFFFFFFF);
      } else if (pchange.address != 3) {
        env->regs[R_EAX] = do_syscall(env, env->regs[R_EAX], env->regs[R_EBX], env->regs[R_ECX], env->regs[R_EDX], env->regs[R_ESI], env->regs[R_EDI], env->regs[R_EBP], 0, 0);
      }               
    }
#endif

    // wrong for system, we need this
    if (flags & IS_WRITE) {
      void *base;
      if (flags & IS_MEM) { base = g2h(pchange.address); }
      else { base = ((void *)env) + pchange.address; }
      memcpy(base, &pchange.data, (flags&SIZE_MASK) >> 3);
    }
#endif
    ret++;
  }
  return ret;
}

void run_QIRA_mods(CPUArchState *env, int this_id);
void run_QIRA_mods(CPUArchState *env, int this_id) {
  char fn[PATH_MAX];
  sprintf(fn, "/tmp/qira_logs/%d_mods", this_id);
  int qira_log_fd = open(fn, O_RDONLY);
  if (qira_log_fd == -1) return;

  // seek past the header
  lseek(qira_log_fd, sizeof(struct logstate), SEEK_SET);

  // run all the changes in this file
  int count = run_QIRA_log_from_fd(env, qira_log_fd, 0xFFFFFFFF);

  close(qira_log_fd);

  printf("+++ REPLAY %d MODS DONE with entry count %d\n", this_id, count);
}

void run_QIRA_log(CPUArchState *env, int this_id, int to_change);
void run_QIRA_log(CPUArchState *env, int this_id, int to_change) {
  char fn[PATH_MAX];
  sprintf(fn, "/tmp/qira_logs/%d", this_id);

  int qira_log_fd, qira_log_fd_ = open(fn, O_RDONLY);
  // qira_log_fd_ must be 30, if it isn't, i'm not sure what happened
  dup2(qira_log_fd_, 100+this_id);
  close(qira_log_fd_);
  qira_log_fd = 100+this_id;

  struct logstate plogstate;
  if (read(qira_log_fd, &plogstate, sizeof(plogstate)) != sizeof(plogstate)) {
    printf("HEADER READ ISSUE!\n");
    return;
  }

  printf("+++ REPLAY %d START on fd %d(%d)\n", this_id, qira_log_fd, qira_log_fd_);

  // check if this one has a parent and recurse here
  // BUG: FD ISSUE!
  QIRA_DEBUG("parent is %d with first_change %d\n", plogstate.parent_id, plogstate.first_changelist_number);
  if (plogstate.parent_id != -1) {
    run_QIRA_log(env, plogstate.parent_id, plogstate.first_changelist_number);
  }

  int count = run_QIRA_log_from_fd(env, qira_log_fd, to_change);

  close(qira_log_fd);

  printf("+++ REPLAY %d DONE to %d with entry count %d\n", this_id, to_change, count);
}

bool is_filtered_address(target_ulong pc);
bool is_filtered_address(target_ulong pc) {
  // to remove the warning
  uint64_t bpc = (uint64_t)pc;
  // TODO(geohot): FIX THIS!, filter anything that isn't the user binary and not dynamic
  if (unlikely(GLOBAL_tracelibraries)) {
    return false;
  } else {
    return ((bpc > 0x40000000 && bpc < 0xf6800000) || bpc >= 0x100000000);
  }
}

void real_target_disas(FILE *out, CPUArchState *env, target_ulong code, target_ulong size, int flags);
void target_disas(FILE *out, CPUArchState *env, target_ulong code, target_ulong size, int flags) {
  OPEN_GLOBAL_ASM_FILE

  if (is_filtered_address(code)) return;

  flock(fileno(GLOBAL_asm_file), LOCK_EX);
  real_target_disas(GLOBAL_asm_file, env, code, size, flags);
  flock(fileno(GLOBAL_asm_file), LOCK_UN);

  fflush(GLOBAL_asm_file);
}


int GLOBAL_last_was_syscall = 0;
uint32_t GLOBAL_last_fork_change = -1;
target_long last_pc = 0;

void write_out_base(CPUArchState *env, int id);

void write_out_base(CPUArchState *env, int id) {
#ifdef QEMU_USER
  CPUState *cpu = ENV_GET_CPU(env);
  TaskState *ts = (TaskState *)cpu->opaque;

  char fn[PATH_MAX];
  char envfn[PATH_MAX];

  sprintf(envfn, "/tmp/qira_logs/%d_env", id);
  FILE *envf = fopen(envfn, "wb");

  // could still be wrong, clipping on env vars
  target_ulong ss = ts->info->start_stack;
  target_ulong se = (ts->info->arg_end + (TARGET_PAGE_SIZE - 1)) & TARGET_PAGE_MASK;

  /*while (h2g_valid(g2h(se))) {
    printf("%x\n", g2h(se));
    fflush(stdout);
    se += TARGET_PAGE_SIZE;
  }*/

  //target_ulong ss = ts->info->arg_start;
  //target_ulong se = ts->info->arg_end;

  fwrite(g2h(ss), 1, se-ss, envf);
  fclose(envf);

  sprintf(fn, "/tmp/qira_logs/%d_base", id);
  FILE *f = fopen(fn, "w");


  // code copied from linux-user/syscall.c
  FILE *maps = fopen("/proc/self/maps", "r");
  char *line = NULL;
  size_t len = 0;
  while (getline(&line, &len, maps) != -1) {
    int fields, dev_maj, dev_min, inode;
    uint64_t min, max, offset;
    char flag_r, flag_w, flag_x, flag_p;
    char path[512] = "";
    fields = sscanf(line, "%"PRIx64"-%"PRIx64" %c%c%c%c %"PRIx64" %x:%x %d"
                    " %512s", &min, &max, &flag_r, &flag_w, &flag_x,
                    &flag_p, &offset, &dev_maj, &dev_min, &inode, path);
    if ((fields < 10) || (fields > 11)) { continue; }

    if (h2g_valid(min) && h2g_valid(max) && strlen(path) && flag_w == '-') {
      fprintf(f, TARGET_ABI_FMT_lx "-" TARGET_ABI_FMT_lx " %"PRIx64" %s\n", h2g(min), h2g(max), offset, path);
      //printf("%p - %p -- %s", h2g(min), h2g(max), line);
      //fflush(stdout);
    }

    /*printf("%s", line);
    fflush(stdout);*/
  }
  fclose(maps);

  // env
  fprintf(f, TARGET_ABI_FMT_lx "-" TARGET_ABI_FMT_lx " %"PRIx64" %s\n", ss, se, (uint64_t)0, envfn);

  fclose(f);
#endif
}

/* Interpret pseudo code in tb. */
uintptr_t tcg_qemu_tb_exec(CPUArchState *env, uint8_t *tb_ptr)
{
#ifdef QIRA_TRACKING
    CPUState *cpu = ENV_GET_CPU(env);
    TranslationBlock *tb = cpu->current_tb;
    //TaskState *ts = (TaskState *)cpu->opaque;

    if (unlikely(GLOBAL_QIRA_did_init == 0)) { 
      // get next id
      if (GLOBAL_id == -1) { GLOBAL_id = get_next_id(); }

      // these are the base libraries we load
      write_out_base(env, GLOBAL_id);

      init_QIRA(env, GLOBAL_id);

      // these three arguments (parent_id, start_clnum, id) must be passed into QIRA
      // this now runs after init_QIRA
      if (GLOBAL_parent_id != -1) {
        run_QIRA_log(env, GLOBAL_parent_id, GLOBAL_start_clnum);
        run_QIRA_mods(env, GLOBAL_id);
      }

      return 0;
    }

    if (unlikely(GLOBAL_logstate->this_pid != getpid())) {
      GLOBAL_start_clnum = GLOBAL_last_fork_change + 1;
      GLOBAL_parent_id = GLOBAL_id;

      // BUG: race condition
      GLOBAL_id = get_next_id();

      // this fixes the PID
      init_QIRA(env, GLOBAL_id);
    }

    // set this every time, it's not in shmem
    GLOBAL_last_fork_change = GLOBAL_logstate->changelist_number;

    if (GLOBAL_last_was_syscall) {
      #ifdef R_EAX
        add_change((void *)&env->regs[R_EAX] - (void *)env, env->regs[R_EAX], IS_WRITE | (sizeof(target_ulong)<<3));
      #endif
      GLOBAL_last_was_syscall = 0;
    }

    if (is_filtered_address(tb->pc)) {
      GLOBAL_logstate->is_filtered = 1;
    } else {
      if (GLOBAL_logstate->is_filtered == 1) {
        commit_pending_changes();
        GLOBAL_logstate->is_filtered = 0;
      }
      GLOBAL_logstate->changelist_number++;
      add_change(tb->pc, tb->size, IS_START);
    }


    QIRA_DEBUG("set changelist %d at %x(%d)\n", GLOBAL_logstate->changelist_number, tb->pc, tb->size);
#endif

    long tcg_temps[CPU_TEMP_BUF_NLONGS];
    uintptr_t sp_value = (uintptr_t)(tcg_temps + CPU_TEMP_BUF_NLONGS);
    uintptr_t next_tb = 0;

    tci_reg[TCG_AREG0] = (tcg_target_ulong)env;
    tci_reg[TCG_REG_CALL_STACK] = sp_value;
    assert(tb_ptr);

    for (;;) {
        TCGOpcode opc = tb_ptr[0];
        //printf("exec : %d\n", opc);
#if !defined(NDEBUG)
        uint8_t op_size = tb_ptr[1];
        uint8_t *old_code_ptr = tb_ptr;
#endif
        tcg_target_ulong t0;
        tcg_target_ulong t1;
        tcg_target_ulong t2;
        tcg_target_ulong a0,a1,a2,a3;
        tcg_target_ulong label;
        TCGCond condition;
        target_ulong taddr;
        uint8_t tmp8;
        uint16_t tmp16;
        uint32_t tmp32;
        uint64_t tmp64;
#if TCG_TARGET_REG_BITS == 32
        uint64_t v64;
#endif
        TCGMemOp memop;

#if defined(GETPC)
        tci_tb_ptr = (uintptr_t)tb_ptr;
#endif

        /* Skip opcode and size entry. */
        tb_ptr += 2;

        switch (opc) {
        case INDEX_op_end:
        case INDEX_op_nop:
            break;
        case INDEX_op_nop1:
        case INDEX_op_nop2:
        case INDEX_op_nop3:
        case INDEX_op_nopn:
        case INDEX_op_discard:
            TODO();
            break;
        case INDEX_op_set_label:
            TODO();
            break;
        case INDEX_op_call:
            t0 = tci_read_ri(&tb_ptr);
            a0 = tci_read_reg(TCG_REG_R0);
            a1 = tci_read_reg(TCG_REG_R1);
            a2 = tci_read_reg(TCG_REG_R2);
            a3 = tci_read_reg(TCG_REG_R3);
            //printf("op_call: %X\n", t0);
            // helper_function raise_interrupt, load_seg
#ifdef R_EAX
            struct change *a = NULL;

            if ((void*)t0 == helper_load_seg) {
              if (GLOBAL_logstate->is_filtered == 1) {
                commit_pending_changes();
              }
              a = track_syscall_begin(env, FAKE_SYSCALL_LOADSEG);
              a->data = a1<<32 | a2;
              //printf("LOAD SEG %x %x %x %x\n", a0, a1, a2, a3);
            } else if ((void*)t0 == helper_raise_interrupt) {
              if (GLOBAL_logstate->is_filtered == 1) {
                commit_pending_changes();
                // syscalls always get a change?
                /*GLOBAL_logstate->changelist_number++;
                add_change(tb->pc, tb->size, IS_START);*/
              }
              a = track_syscall_begin(env, env->regs[R_EAX]);
              GLOBAL_last_was_syscall = 1;
            }
#endif

#if TCG_TARGET_REG_BITS == 32
            tmp64 = ((helper_function)t0)(a0,a1,a2,a3,
                                          tci_read_reg(TCG_REG_R5),
                                          tci_read_reg(TCG_REG_R6),
                                          tci_read_reg(TCG_REG_R7),
                                          tci_read_reg(TCG_REG_R8),
                                          tci_read_reg(TCG_REG_R9),
                                          tci_read_reg(TCG_REG_R10));
            tci_write_reg(TCG_REG_R0, tmp64);
            tci_write_reg(TCG_REG_R1, tmp64 >> 32);
#else
            tmp64 = ((helper_function)t0)(a0,a1,a2,a3,
                                          tci_read_reg(TCG_REG_R5));
            tci_write_reg(TCG_REG_R0, tmp64);
#endif
            break;
        case INDEX_op_br:
            label = tci_read_label(&tb_ptr);
            assert(tb_ptr == old_code_ptr + op_size);
            tb_ptr = (uint8_t *)label;
            continue;
        case INDEX_op_setcond_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r32(&tb_ptr);
            t2 = tci_read_ri32(&tb_ptr);
            condition = *tb_ptr++;
            tci_write_reg32(t0, tci_compare32(t1, t2, condition));
            break;
#if TCG_TARGET_REG_BITS == 32
        case INDEX_op_setcond2_i32:
            t0 = *tb_ptr++;
            tmp64 = tci_read_r64(&tb_ptr);
            v64 = tci_read_ri64(&tb_ptr);
            condition = *tb_ptr++;
            tci_write_reg32(t0, tci_compare64(tmp64, v64, condition));
            break;
#elif TCG_TARGET_REG_BITS == 64
        case INDEX_op_setcond_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r64(&tb_ptr);
            t2 = tci_read_ri64(&tb_ptr);
            condition = *tb_ptr++;
            tci_write_reg64(t0, tci_compare64(t1, t2, condition));
            break;
#endif
        case INDEX_op_mov_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r32(&tb_ptr);
            tci_write_reg32(t0, t1);
            break;
        case INDEX_op_movi_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_i32(&tb_ptr);
            tci_write_reg32(t0, t1);
            break;

            /* Load/store operations (32 bit). */

        case INDEX_op_ld8u_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r(&tb_ptr);
            t2 = tci_read_s32(&tb_ptr);
            track_read(t1, t2, *(uint8_t *)(t1 + t2), 32);
            tci_write_reg8(t0, *(uint8_t *)(t1 + t2));
            break;
        case INDEX_op_ld8s_i32:
        case INDEX_op_ld16u_i32:
            TODO();
            break;
        case INDEX_op_ld16s_i32:
            TODO();
            break;
        case INDEX_op_ld_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r(&tb_ptr);
            t2 = tci_read_s32(&tb_ptr);
            track_read(t1, t2, *(uint32_t *)(t1 + t2), 32);
            tci_write_reg32(t0, *(uint32_t *)(t1 + t2));
            break;
        case INDEX_op_st8_i32:
            t0 = tci_read_r8(&tb_ptr);
            t1 = tci_read_r(&tb_ptr);
            t2 = tci_read_s32(&tb_ptr);
            track_write(t1, t2, t0, 32);
            *(uint8_t *)(t1 + t2) = t0;
            break;
        case INDEX_op_st16_i32:
            t0 = tci_read_r16(&tb_ptr);
            t1 = tci_read_r(&tb_ptr);
            t2 = tci_read_s32(&tb_ptr);
            track_write(t1, t2, t0, 32);
            *(uint16_t *)(t1 + t2) = t0;
            break;
        case INDEX_op_st_i32:
            t0 = tci_read_r32(&tb_ptr);
            t1 = tci_read_r(&tb_ptr);
            t2 = tci_read_s32(&tb_ptr);
            assert(t1 != sp_value || (int32_t)t2 < 0);
            track_write(t1, t2, t0, 32);
            *(uint32_t *)(t1 + t2) = t0;
            break;

            /* Arithmetic operations (32 bit). */

        case INDEX_op_add_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr);
            t2 = tci_read_ri32(&tb_ptr);
            tci_write_reg32(t0, t1 + t2);
            break;
        case INDEX_op_sub_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr);
            t2 = tci_read_ri32(&tb_ptr);
            tci_write_reg32(t0, t1 - t2);
            break;
        case INDEX_op_mul_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr);
            t2 = tci_read_ri32(&tb_ptr);
            tci_write_reg32(t0, t1 * t2);
            break;
#if TCG_TARGET_HAS_div_i32
        case INDEX_op_div_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr);
            t2 = tci_read_ri32(&tb_ptr);
            tci_write_reg32(t0, (int32_t)t1 / (int32_t)t2);
            break;
        case INDEX_op_divu_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr);
            t2 = tci_read_ri32(&tb_ptr);
            tci_write_reg32(t0, t1 / t2);
            break;
        case INDEX_op_rem_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr);
            t2 = tci_read_ri32(&tb_ptr);
            tci_write_reg32(t0, (int32_t)t1 % (int32_t)t2);
            break;
        case INDEX_op_remu_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr);
            t2 = tci_read_ri32(&tb_ptr);
            tci_write_reg32(t0, t1 % t2);
            break;
#elif TCG_TARGET_HAS_div2_i32
        case INDEX_op_div2_i32:
        case INDEX_op_divu2_i32:
            TODO();
            break;
#endif
        case INDEX_op_and_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr);
            t2 = tci_read_ri32(&tb_ptr);
            tci_write_reg32(t0, t1 & t2);
            break;
        case INDEX_op_or_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr);
            t2 = tci_read_ri32(&tb_ptr);
            tci_write_reg32(t0, t1 | t2);
            break;
        case INDEX_op_xor_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr);
            t2 = tci_read_ri32(&tb_ptr);
            tci_write_reg32(t0, t1 ^ t2);
            break;

            /* Shift/rotate operations (32 bit). */

        case INDEX_op_shl_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr);
            t2 = tci_read_ri32(&tb_ptr);
            tci_write_reg32(t0, t1 << (t2 & 31));
            break;
        case INDEX_op_shr_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr);
            t2 = tci_read_ri32(&tb_ptr);
            tci_write_reg32(t0, t1 >> (t2 & 31));
            break;
        case INDEX_op_sar_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr);
            t2 = tci_read_ri32(&tb_ptr);
            tci_write_reg32(t0, ((int32_t)t1 >> (t2 & 31)));
            break;
#if TCG_TARGET_HAS_rot_i32
        case INDEX_op_rotl_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr);
            t2 = tci_read_ri32(&tb_ptr);
            tci_write_reg32(t0, rol32(t1, t2 & 31));
            break;
        case INDEX_op_rotr_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_ri32(&tb_ptr);
            t2 = tci_read_ri32(&tb_ptr);
            tci_write_reg32(t0, ror32(t1, t2 & 31));
            break;
#endif
#if TCG_TARGET_HAS_deposit_i32
        case INDEX_op_deposit_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r32(&tb_ptr);
            t2 = tci_read_r32(&tb_ptr);
            tmp16 = *tb_ptr++;
            tmp8 = *tb_ptr++;
            tmp32 = (((1 << tmp8) - 1) << tmp16);
            tci_write_reg32(t0, (t1 & ~tmp32) | ((t2 << tmp16) & tmp32));
            break;
#endif
        case INDEX_op_brcond_i32:
            t0 = tci_read_r32(&tb_ptr);
            t1 = tci_read_ri32(&tb_ptr);
            condition = *tb_ptr++;
            label = tci_read_label(&tb_ptr);
            if (tci_compare32(t0, t1, condition)) {
                assert(tb_ptr == old_code_ptr + op_size);
                tb_ptr = (uint8_t *)label;
                continue;
            }
            break;
#if TCG_TARGET_REG_BITS == 32
        case INDEX_op_add2_i32:
            t0 = *tb_ptr++;
            t1 = *tb_ptr++;
            tmp64 = tci_read_r64(&tb_ptr);
            tmp64 += tci_read_r64(&tb_ptr);
            tci_write_reg64(t1, t0, tmp64);
            break;
        case INDEX_op_sub2_i32:
            t0 = *tb_ptr++;
            t1 = *tb_ptr++;
            tmp64 = tci_read_r64(&tb_ptr);
            tmp64 -= tci_read_r64(&tb_ptr);
            tci_write_reg64(t1, t0, tmp64);
            break;
        case INDEX_op_brcond2_i32:
            tmp64 = tci_read_r64(&tb_ptr);
            v64 = tci_read_ri64(&tb_ptr);
            condition = *tb_ptr++;
            label = tci_read_label(&tb_ptr);
            if (tci_compare64(tmp64, v64, condition)) {
                assert(tb_ptr == old_code_ptr + op_size);
                tb_ptr = (uint8_t *)label;
                continue;
            }
            break;
        case INDEX_op_mulu2_i32:
            t0 = *tb_ptr++;
            t1 = *tb_ptr++;
            t2 = tci_read_r32(&tb_ptr);
            tmp64 = tci_read_r32(&tb_ptr);
            tci_write_reg64(t1, t0, t2 * tmp64);
            break;
#endif /* TCG_TARGET_REG_BITS == 32 */
#if TCG_TARGET_HAS_ext8s_i32
        case INDEX_op_ext8s_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r8s(&tb_ptr);
            tci_write_reg32(t0, t1);
            break;
#endif
#if TCG_TARGET_HAS_ext16s_i32
        case INDEX_op_ext16s_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r16s(&tb_ptr);
            tci_write_reg32(t0, t1);
            break;
#endif
#if TCG_TARGET_HAS_ext8u_i32
        case INDEX_op_ext8u_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r8(&tb_ptr);
            tci_write_reg32(t0, t1);
            break;
#endif
#if TCG_TARGET_HAS_ext16u_i32
        case INDEX_op_ext16u_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r16(&tb_ptr);
            tci_write_reg32(t0, t1);
            break;
#endif
#if TCG_TARGET_HAS_bswap16_i32
        case INDEX_op_bswap16_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r16(&tb_ptr);
            tci_write_reg32(t0, bswap16(t1));
            break;
#endif
#if TCG_TARGET_HAS_bswap32_i32
        case INDEX_op_bswap32_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r32(&tb_ptr);
            tci_write_reg32(t0, bswap32(t1));
            break;
#endif
#if TCG_TARGET_HAS_not_i32
        case INDEX_op_not_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r32(&tb_ptr);
            tci_write_reg32(t0, ~t1);
            break;
#endif
#if TCG_TARGET_HAS_neg_i32
        case INDEX_op_neg_i32:
            t0 = *tb_ptr++;
            t1 = tci_read_r32(&tb_ptr);
            tci_write_reg32(t0, -t1);
            break;
#endif
#if TCG_TARGET_REG_BITS == 64
        case INDEX_op_mov_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r64(&tb_ptr);
            tci_write_reg64(t0, t1);
            break;
        case INDEX_op_movi_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_i64(&tb_ptr);
            tci_write_reg64(t0, t1);
            break;

            /* Load/store operations (64 bit). */

        case INDEX_op_ld8u_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r(&tb_ptr);
            t2 = tci_read_s32(&tb_ptr);
            track_read(t1, t2, *(uint8_t *)(t1 + t2), 8);
            tci_write_reg8(t0, *(uint8_t *)(t1 + t2));
            break;
        case INDEX_op_ld8s_i64:
        case INDEX_op_ld16u_i64:
        case INDEX_op_ld16s_i64:
            TODO();
            break;
        case INDEX_op_ld32u_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r(&tb_ptr);
            t2 = tci_read_s32(&tb_ptr);
            track_read(t1, t2, *(uint32_t *)(t1 + t2), 32);
            tci_write_reg32(t0, *(uint32_t *)(t1 + t2));
            break;
        case INDEX_op_ld32s_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r(&tb_ptr);
            t2 = tci_read_s32(&tb_ptr);
            track_read(t1, t2, *(int32_t *)(t1 + t2), 32);
            tci_write_reg32s(t0, *(int32_t *)(t1 + t2));
            break;
        case INDEX_op_ld_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r(&tb_ptr);
            t2 = tci_read_s32(&tb_ptr);
            track_read(t1, t2, *(uint64_t *)(t1 + t2), 64);
            tci_write_reg64(t0, *(uint64_t *)(t1 + t2));
            break;
        case INDEX_op_st8_i64:
            t0 = tci_read_r8(&tb_ptr);
            t1 = tci_read_r(&tb_ptr);
            t2 = tci_read_s32(&tb_ptr);
            track_write(t1, t2, t0, 64);
            *(uint8_t *)(t1 + t2) = t0;
            break;
        case INDEX_op_st16_i64:
            t0 = tci_read_r16(&tb_ptr);
            t1 = tci_read_r(&tb_ptr);
            t2 = tci_read_s32(&tb_ptr);
            track_write(t1, t2, t0, 64);
            *(uint16_t *)(t1 + t2) = t0;
            break;
        case INDEX_op_st32_i64:
            t0 = tci_read_r32(&tb_ptr);
            t1 = tci_read_r(&tb_ptr);
            t2 = tci_read_s32(&tb_ptr);
            track_write(t1, t2, t0, 64);
            *(uint32_t *)(t1 + t2) = t0;
            break;
        case INDEX_op_st_i64:
            t0 = tci_read_r64(&tb_ptr);
            t1 = tci_read_r(&tb_ptr);
            t2 = tci_read_s32(&tb_ptr);
            assert(t1 != sp_value || (int32_t)t2 < 0);
            track_write(t1, t2, t0, 64);
            *(uint64_t *)(t1 + t2) = t0;
            break;

            /* Arithmetic operations (64 bit). */

        case INDEX_op_add_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr);
            t2 = tci_read_ri64(&tb_ptr);
            tci_write_reg64(t0, t1 + t2);
            break;
        case INDEX_op_sub_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr);
            t2 = tci_read_ri64(&tb_ptr);
            tci_write_reg64(t0, t1 - t2);
            break;
        case INDEX_op_mul_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr);
            t2 = tci_read_ri64(&tb_ptr);
            tci_write_reg64(t0, t1 * t2);
            break;
#if TCG_TARGET_HAS_div_i64
        case INDEX_op_div_i64:
        case INDEX_op_divu_i64:
        case INDEX_op_rem_i64:
        case INDEX_op_remu_i64:
            TODO();
            break;
#elif TCG_TARGET_HAS_div2_i64
        case INDEX_op_div2_i64:
        case INDEX_op_divu2_i64:
            TODO();
            break;
#endif
        case INDEX_op_and_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr);
            t2 = tci_read_ri64(&tb_ptr);
            tci_write_reg64(t0, t1 & t2);
            break;
        case INDEX_op_or_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr);
            t2 = tci_read_ri64(&tb_ptr);
            tci_write_reg64(t0, t1 | t2);
            break;
        case INDEX_op_xor_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr);
            t2 = tci_read_ri64(&tb_ptr);
            tci_write_reg64(t0, t1 ^ t2);
            break;

            /* Shift/rotate operations (64 bit). */

        case INDEX_op_shl_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr);
            t2 = tci_read_ri64(&tb_ptr);
            tci_write_reg64(t0, t1 << (t2 & 63));
            break;
        case INDEX_op_shr_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr);
            t2 = tci_read_ri64(&tb_ptr);
            tci_write_reg64(t0, t1 >> (t2 & 63));
            break;
        case INDEX_op_sar_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr);
            t2 = tci_read_ri64(&tb_ptr);
            tci_write_reg64(t0, ((int64_t)t1 >> (t2 & 63)));
            break;
#if TCG_TARGET_HAS_rot_i64
        case INDEX_op_rotl_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr);
            t2 = tci_read_ri64(&tb_ptr);
            tci_write_reg64(t0, rol64(t1, t2 & 63));
            break;
        case INDEX_op_rotr_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_ri64(&tb_ptr);
            t2 = tci_read_ri64(&tb_ptr);
            tci_write_reg64(t0, ror64(t1, t2 & 63));
            break;
#endif
#if TCG_TARGET_HAS_deposit_i64
        case INDEX_op_deposit_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r64(&tb_ptr);
            t2 = tci_read_r64(&tb_ptr);
            tmp16 = *tb_ptr++;
            tmp8 = *tb_ptr++;
            tmp64 = (((1ULL << tmp8) - 1) << tmp16);
            tci_write_reg64(t0, (t1 & ~tmp64) | ((t2 << tmp16) & tmp64));
            break;
#endif
        case INDEX_op_brcond_i64:
            t0 = tci_read_r64(&tb_ptr);
            t1 = tci_read_ri64(&tb_ptr);
            condition = *tb_ptr++;
            label = tci_read_label(&tb_ptr);
            if (tci_compare64(t0, t1, condition)) {
                assert(tb_ptr == old_code_ptr + op_size);
                tb_ptr = (uint8_t *)label;
                continue;
            }
            break;
#if TCG_TARGET_HAS_ext8u_i64
        case INDEX_op_ext8u_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r8(&tb_ptr);
            tci_write_reg64(t0, t1);
            break;
#endif
#if TCG_TARGET_HAS_ext8s_i64
        case INDEX_op_ext8s_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r8s(&tb_ptr);
            tci_write_reg64(t0, t1);
            break;
#endif
#if TCG_TARGET_HAS_ext16s_i64
        case INDEX_op_ext16s_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r16s(&tb_ptr);
            tci_write_reg64(t0, t1);
            break;
#endif
#if TCG_TARGET_HAS_ext16u_i64
        case INDEX_op_ext16u_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r16(&tb_ptr);
            tci_write_reg64(t0, t1);
            break;
#endif
#if TCG_TARGET_HAS_ext32s_i64
        case INDEX_op_ext32s_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r32s(&tb_ptr);
            tci_write_reg64(t0, t1);
            break;
#endif
#if TCG_TARGET_HAS_ext32u_i64
        case INDEX_op_ext32u_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r32(&tb_ptr);
            tci_write_reg64(t0, t1);
            break;
#endif
#if TCG_TARGET_HAS_bswap16_i64
        case INDEX_op_bswap16_i64:
            TODO();
            t0 = *tb_ptr++;
            t1 = tci_read_r16(&tb_ptr);
            tci_write_reg64(t0, bswap16(t1));
            break;
#endif
#if TCG_TARGET_HAS_bswap32_i64
        case INDEX_op_bswap32_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r32(&tb_ptr);
            tci_write_reg64(t0, bswap32(t1));
            break;
#endif
#if TCG_TARGET_HAS_bswap64_i64
        case INDEX_op_bswap64_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r64(&tb_ptr);
            tci_write_reg64(t0, bswap64(t1));
            break;
#endif
#if TCG_TARGET_HAS_not_i64
        case INDEX_op_not_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r64(&tb_ptr);
            tci_write_reg64(t0, ~t1);
            break;
#endif
#if TCG_TARGET_HAS_neg_i64
        case INDEX_op_neg_i64:
            t0 = *tb_ptr++;
            t1 = tci_read_r64(&tb_ptr);
            tci_write_reg64(t0, -t1);
            break;
#endif
#endif /* TCG_TARGET_REG_BITS == 64 */

            /* QEMU specific operations. */

#if TARGET_LONG_BITS > TCG_TARGET_REG_BITS
        case INDEX_op_debug_insn_start:
            TODO();
            break;
#else
        case INDEX_op_debug_insn_start:
            TODO();
            break;
#endif
        case INDEX_op_exit_tb:
            next_tb = *(uint64_t *)tb_ptr;
            goto exit;
            break;
        case INDEX_op_goto_tb:
            t0 = tci_read_i32(&tb_ptr);
            assert(tb_ptr == old_code_ptr + op_size);
            //printf("goto_tb: %lx\n", t0);
            tb_ptr += (int32_t)t0;
            continue;
        case INDEX_op_qemu_ld_i32:
            t0 = *tb_ptr++;
            taddr = tci_read_ulong(&tb_ptr);
            memop = tci_read_i(&tb_ptr);
            switch (memop) {
            case MO_UB:
                tmp32 = qemu_ld_ub;
                break;
            case MO_SB:
                tmp32 = (int8_t)qemu_ld_ub;
                break;
            case MO_LEUW:
                tmp32 = qemu_ld_leuw;
                break;
            case MO_LESW:
                tmp32 = (int16_t)qemu_ld_leuw;
                break;
            case MO_LEUL:
                tmp32 = qemu_ld_leul;
                break;
            case MO_BEUW:
                tmp32 = qemu_ld_beuw;
                break;
            case MO_BESW:
                tmp32 = (int16_t)qemu_ld_beuw;
                break;
            case MO_BEUL:
                tmp32 = qemu_ld_beul;
                break;
            default:
                tcg_abort();
            }
            tci_write_reg(t0, tmp32);
            break;
        case INDEX_op_qemu_ld_i64:
            t0 = *tb_ptr++;
            if (TCG_TARGET_REG_BITS == 32) {
                t1 = *tb_ptr++;
            }
            taddr = tci_read_ulong(&tb_ptr);
            memop = tci_read_i(&tb_ptr);
            switch (memop) {
            case MO_UB:
                tmp64 = qemu_ld_ub;
                break;
            case MO_SB:
                tmp64 = (int8_t)qemu_ld_ub;
                break;
            case MO_LEUW:
                tmp64 = qemu_ld_leuw;
                break;
            case MO_LESW:
                tmp64 = (int16_t)qemu_ld_leuw;
                break;
            case MO_LEUL:
                tmp64 = qemu_ld_leul;
                break;
            case MO_LESL:
                tmp64 = (int32_t)qemu_ld_leul;
                break;
            case MO_LEQ:
                tmp64 = qemu_ld_leq;
                break;
            case MO_BEUW:
                tmp64 = qemu_ld_beuw;
                break;
            case MO_BESW:
                tmp64 = (int16_t)qemu_ld_beuw;
                break;
            case MO_BEUL:
                tmp64 = qemu_ld_beul;
                break;
            case MO_BESL:
                tmp64 = (int32_t)qemu_ld_beul;
                break;
            case MO_BEQ:
                tmp64 = qemu_ld_beq;
                break;
            default:
                tcg_abort();
            }
            tci_write_reg(t0, tmp64);
            if (TCG_TARGET_REG_BITS == 32) {
                tci_write_reg(t1, tmp64 >> 32);
            }
            break;
        case INDEX_op_qemu_st_i32:
            t0 = tci_read_r(&tb_ptr);
            taddr = tci_read_ulong(&tb_ptr);
            memop = tci_read_i(&tb_ptr);
            switch (memop) {
            case MO_UB:
                qemu_st_b(t0);
                break;
            case MO_LEUW:
                qemu_st_lew(t0);
                break;
            case MO_LEUL:
                qemu_st_lel(t0);
                break;
            case MO_BEUW:
                qemu_st_bew(t0);
                break;
            case MO_BEUL:
                qemu_st_bel(t0);
                break;
            default:
                tcg_abort();
            }
            break;
        case INDEX_op_qemu_st_i64:
            tmp64 = tci_read_r64(&tb_ptr);
            taddr = tci_read_ulong(&tb_ptr);
            memop = tci_read_i(&tb_ptr);
            switch (memop) {
            case MO_UB:
                qemu_st_b(tmp64);
                break;
            case MO_LEUW:
                qemu_st_lew(tmp64);
                break;
            case MO_LEUL:
                qemu_st_lel(tmp64);
                break;
            case MO_LEQ:
                qemu_st_leq(tmp64);
                break;
            case MO_BEUW:
                qemu_st_bew(tmp64);
                break;
            case MO_BEUL:
                qemu_st_bel(tmp64);
                break;
            case MO_BEQ:
                qemu_st_beq(tmp64);
                break;
            default:
                tcg_abort();
            }
            break;
        default:
            TODO();
            break;
        }
        assert(tb_ptr == old_code_ptr + op_size);
    }
exit:
#ifdef QIRA_TRACKING
    // this fixes the jump instruction merging bug
    // with the last_pc hack for ARM, might break some x86 reps
    if (next_tb != 0 && last_pc != tb->pc) {
      next_tb = 0;
    }
#endif
    last_pc = tb->pc;
    return next_tb;
}

