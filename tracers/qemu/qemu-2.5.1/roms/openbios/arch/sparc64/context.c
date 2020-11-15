/*
 * context switching
 * 2003-10 by SONE Takeshi
 */

#include "config.h"
#include "kernel/kernel.h"
#include "context.h"
#include "libopenbios/sys_info.h"
#include "boot.h"
#include "openbios.h"

#define MAIN_STACK_SIZE 16384
#define IMAGE_STACK_SIZE 4096*4

#define debug printk

static void start_main(void); /* forward decl. */
void __exit_context(void); /* assembly routine */

/*
 * Main context structure
 * It is placed at the bottom of our stack, and loaded by assembly routine
 * to start us up.
 */
static struct context main_ctx = {
    .regs[REG_SP] = (uint64_t) &_estack - STACK_BIAS - 96,
    .pc = (uint64_t) start_main,
    .npc = (uint64_t) start_main + 4,
    .return_addr = (uint64_t) __exit_context,
};

/* This is used by assembly routine to load/store the context which
 * it is to switch/switched.  */
struct context * volatile __context = &main_ctx;

/* Stack for loaded ELF image */
static uint8_t image_stack[IMAGE_STACK_SIZE];

/* Pointer to startup context (physical address) */
unsigned long __boot_ctx;

/*
 * Main starter
 * This is the C function that runs first.
 */
static void start_main(void)
{
    /* Save startup context, so we can refer to it later.
     * We have to keep it in physical address since we will relocate. */
    __boot_ctx = virt_to_phys(__context);

    /* Start the real fun */
    openbios();

    /* Returning from here should jump to __exit_context */
    __context = boot_ctx;
}

static uint64_t ALIGN_SIZE(uint64_t x, uint64_t a)
{
    return (x + a - 1) & ~(a-1);
}

/* Setup a new context using the given stack.
 */
struct context *
init_context(uint8_t *stack, uint64_t stack_size, int num_params)
{
    struct context *ctx;
    uint8_t *stack_top = stack + stack_size;

    ctx = (struct context *)
	(stack_top - ALIGN_SIZE(sizeof(*ctx) + num_params*sizeof(uint64_t), sizeof(uint64_t)));
    memset(ctx, 0, sizeof(*ctx));

    /* Fill in reasonable default for flat memory model */
    ctx->regs[REG_SP] = virt_to_phys(stack_top - STACK_BIAS - 192);
    ctx->return_addr = virt_to_phys(__exit_context);

    return ctx;
}

/* Switch to another context. */
struct context *switch_to(struct context *ctx)
{
    struct context *save, *ret;

    debug("switching to new context: entry point %#llx stack 0x%016llx\n", ctx->pc, ctx->regs[REG_SP]);
    save = __context;
    __context = ctx;
    //asm ("pushl %cs; call __switch_context");
    asm ("call __switch_context_nosave; nop");
    ret = __context;
    __context = save;
    return ret;
}

/* Start ELF Boot image */
uint64_t start_elf(uint64_t entry_point, uint64_t param)
{
    struct context *ctx;

    ctx = init_context(image_stack, sizeof image_stack, 1);
    ctx->pc = entry_point;
    ctx->param[0] = param;
    //ctx->eax = 0xe1fb007;
    //ctx->ebx = param;

    ctx = switch_to(ctx);
    //return ctx->eax;
    return 0;
}

/* Start client image */
uint64_t start_client_image(uint64_t entry_point, uint64_t cif_handler)
{
    struct context *ctx;

    ctx = init_context(image_stack, sizeof image_stack, 0);
    ctx->pc  = entry_point;
    ctx->npc = entry_point+4;
    ctx->regs[REG_O0] = 0;
    ctx->regs[REG_O0+4] = cif_handler;

    ctx = switch_to(ctx);

    return 0;
}
