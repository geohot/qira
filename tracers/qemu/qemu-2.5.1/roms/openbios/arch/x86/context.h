#ifndef i386_CONTEXT_H
#define i386_CONTEXT_H

struct context {
    /* Stack Segment, placed here because of the alignment issue... */
    uint16_t ss;
    /* Used with sgdt/lgdt */
    uint16_t gdt_limit;
    uint32_t gdt_base;
    /* General registers, accessed with pushal/popal */
    uint32_t edi;
    uint32_t esi;
    uint32_t ebp;
    uint32_t esp; /* points just below eax */
    uint32_t ebx;
    uint32_t edx;
    uint32_t ecx;
    uint32_t eax;
#define ESP_LOC(ctx) (&(ctx)->gs)
    /* Segment registers */
    uint32_t gs;
    uint32_t fs;
    uint32_t es;
    uint32_t ds;
    /* Flags */
    uint32_t eflags;
    /* Code segment:offset */
    uint32_t eip;
    uint32_t cs;
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

#endif /* i386_CONTEXT_H */
