#include "config.h"
#include "libopenbios/bindings.h"
#include "asm/types.h"



/* program counter */
extern ucell            PC;

extern unsigned char    *dict;
extern cell             dicthead;
extern ucell            *last;



struct eregs {
	uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi;
	uint32_t vector;
	uint32_t error_code;
	uint32_t eip;
	uint32_t cs;
	uint32_t eflags;
};

static const char * const exception_names[]= {
	"division by zero",
	"single step",
	"NMI",
	"breakpoint",
	"interrupt overflow",
	"bound range exceeded",
	"invalid opcode",
	"device unavailable",
	"double fault",
	"FPU segment overrun",
	"invalid TSS",
	"segment not present",
	"stack exception",
	"general protection fault",
	"page fault",
	"reserved",
	"floating point exception",
	"alignment check",
	"machine check exception",
};

void do_nothing(void);
void do_nothing(void)
{
	printk("Doing nothing\n");
}

void x86_exception(struct eregs *info);
void x86_exception(struct eregs *info)
{
	if(info->vector <= 18) {
		printk("\nUnexpected Exception: %s",
				exception_names[info->vector]);
	} else {
		printk("\nUnexpected Exception: %d", info->vector);
	}

	printk(
		" @ %02x:%08lx - Halting\n"
		"Code: %d eflags: %08lx\n"
		"eax: %08lx ebx: %08lx ecx: %08lx edx: %08lx\n"
		"edi: %08lx esi: %08lx ebp: %08lx esp: %08lx\n",
		info->cs, (unsigned long)info->eip,
		info->error_code, (unsigned long)info->eflags,
		(unsigned long)info->eax, (unsigned long)info->ebx,
		(unsigned long)info->ecx, (unsigned long)info->edx,
		(unsigned long)info->edi, (unsigned long)info->esi,
		(unsigned long)info->ebp, (unsigned long)info->esp);

        printk("\ndict=0x%x here=0x%x(dict+0x%x) pc=0x%x(dict+0x%x)\n",
               (ucell)dict, (ucell)dict + dicthead, dicthead, PC, PC - (ucell) dict);
        printk("dstackcnt=%d rstackcnt=%d\n",
               dstackcnt, rstackcnt);

	rstackcnt=0;
	dstackcnt=0;

	PC=findword("outer-interpreter");

	info->eip=(uint32_t)&do_nothing;

/*
	for (;;)
		asm("hlt;");
		;
*/
}
