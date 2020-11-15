#ifndef SPARC32_CONTEXT_H
#define SPARC32_CONTEXT_H

struct context {
    /* General registers */
    uint32_t regs[32];
    uint32_t pc;
    uint32_t npc;
#define REG_O0 8
#define REG_SP 14
#define SP_LOC(ctx) (&(ctx)->regs[REG_SP])
    /* Flags */
    /* Optional stack contents */
    uint32_t return_addr;
    uint32_t param[0];
};

/* Create a new context in the given stack */
struct context *
init_context(uint8_t *stack, uint32_t stack_size, int num_param);

/* Switch context */
struct context *switch_to(struct context *);

/* Holds physical address of boot context */
extern unsigned long __boot_ctx;

/* This can always be safely used to refer to the boot context */
#define boot_ctx ((struct context *) phys_to_virt(__boot_ctx))

#endif /* SPARC32_CONTEXT_H */
