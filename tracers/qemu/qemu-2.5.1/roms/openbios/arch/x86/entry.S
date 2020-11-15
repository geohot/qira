	.globl	entry, __switch_context, __exit_context, halt, init_exceptions

	.text
	.align	4

/*
 * Entry point
 * We start execution from here.
 * It is assumed that CPU is in 32-bit protected mode and
 * all segments are 4GB and base zero (flat model).
 */
entry:
	/* Save boot context and switch to our main context.
	 * Main context is statically defined in C.
	 */
	pushl	%cs
	call	__switch_context

	/* We get here when the main context switches back to
	 * the boot context.
	 * Return to previous bootloader.
	 */
	ret

/*
 * Switch execution context
 * This saves registers, segments, and GDT in the stack, then
 * switches the stack, and restores everything from the new stack.
 * This function takes no argument. New stack pointer is
 * taken from global variable __context, and old stack pointer
 * is also saved to __context. This way we can just jump to
 * this routine to get back to the original context.
 *
 * Call this routine with lcall or pushl %cs; call.
 */
__switch_context:
	/* Save everything in current stack */
	pushfl		    /* 56 */
	pushl	%ds	    /* 52 */
	pushl	%es	    /* 48 */
	pushl	%fs	    /* 44 */
	pushl	%gs	    /* 40 */
	pushal		    /* 8 */
	subl	$8, %esp
	movw	%ss, (%esp) /* 0 */
	sgdt	2(%esp)	    /* 2 */

#if 0
	/* Swap %cs and %eip on the stack, so lret will work */
	movl	60(%esp), %eax
	xchgl	%eax, 64(%esp)
	movl	%eax, 60(%esp)
#endif

	/* At this point we don't know if we are on flat segment
	 * or relocated. So compute the address offset from %eip.
	 * Assuming CS.base==DS.base==SS.base.
	 */
	call	1f
1:	popl	%ebx
	subl	$1b, %ebx

	/* Interrupts are not allowed... */
	cli

	/* Current context pointer is our stack pointer */
	movl	%esp, %esi

	/* Normalize the ctx pointer */
	subl	%ebx, %esi

	/* Swap it with new value */
	xchgl	%esi, __context(%ebx)

	/* Adjust new ctx pointer for current address offset */
	addl	%ebx, %esi

	/* Load new %ss and %esp to temporary */
	movzwl	(%esi), %edx
	movl	20(%esi), %eax

	/* Load new GDT */
	lgdt	2(%esi)

	/* Load new stack segment with new GDT */
	movl	%edx, %ss

	/* Set new stack pointer, but we have to adjust it because
	 * pushal saves %esp value before pushal, and we want the value
	 * after pushal.
	 */
	leal	-32(%eax), %esp

	/* Load the rest from new stack */
	popal
	popl	%gs
	popl	%fs
	popl	%es
	popl	%ds
	popfl

	/* Finally, load new %cs and %eip */
	lret

__exit_context:
	/* Get back to the original context */
	pushl	%cs
	call	__switch_context

	/* We get here if the other context attempt to switch to this
	 * dead context. This should not happen. */

halt:
	cli
	hlt
	jmp	halt

/*
 * initialize exception handler. All exceptions end up in the same
 * C function.
 */

init_exceptions:
	pushl	%ebx
	pushl	%edi

        /* Initialize the Interrupt Descriptor table */
        leal    _idt, %edi
        leal    vec0, %ebx
        movl    $(0x08 << 16), %eax     /* cs selector */

1:      movw    %bx, %ax
        movl    %ebx, %edx
        movw    $0x8E00, %dx            /* Interrupt gate - dpl=0, present */
        movl    %eax, 0(%edi)
        movl    %edx, 4(%edi)
        addl    $6, %ebx
        addl    $8, %edi
        cmpl    $_idt_end, %edi
        jne     1b

        /* Load the Interrupt descriptor table */
        lidt    idtarg

	movl 	$0, %eax
	popl	%edi
	popl	%ebx
	ret

vec0:
        pushl   $0 /* error code */
        pushl   $0 /* vector */
        jmp int_hand
vec1:
        pushl   $0 /* error code */
        pushl   $1 /* vector */
        jmp int_hand

vec2:
        pushl   $0 /* error code */
        pushl   $2 /* vector */
        jmp int_hand

vec3:
        pushl   $0 /* error code */
        pushl   $3 /* vector */
        jmp     int_hand

vec4:
        pushl   $0 /* error code */
        pushl   $4 /* vector */
        jmp     int_hand

vec5:
        pushl   $0 /* error code */
        pushl   $5 /* vector */
        jmp     int_hand

vec6:
        pushl   $0 /* error code */
        pushl   $6 /* vector */
        jmp     int_hand
vec7:
        pushl   $0 /* error code */
        pushl   $7 /* vector */
        jmp     int_hand

vec8:
        /* error code */
        pushl   $8 /* vector */
        jmp     int_hand
        .word   0x9090

vec9:
        pushl   $0 /* error code */
        pushl   $9 /* vector */
        jmp int_hand

vec10:
        /* error code */
        pushl   $10 /* vector */
        jmp     int_hand
        .word   0x9090

vec11:
        /* error code */
        pushl   $11 /* vector */
        jmp     int_hand
        .word   0x9090

vec12:
        /* error code */
        pushl   $12 /* vector */
        jmp     int_hand
        .word   0x9090

vec13:
        /* error code */
        pushl   $13 /* vector */
        jmp     int_hand
        .word   0x9090

vec14:
        /* error code */
        pushl   $14 /* vector */
        jmp     int_hand
        .word   0x9090

vec15:
        pushl   $0 /* error code */
        pushl   $15 /* vector */
        jmp     int_hand

vec16:
        pushl   $0 /* error code */
        pushl   $16 /* vector */
        jmp     int_hand

vec17:
        /* error code */
        pushl   $17 /* vector */
        jmp     int_hand
        .word   0x9090

vec18:
        pushl   $0 /* error code */
        pushl   $18 /* vector */
        jmp     int_hand

vec19:
        pushl   $0 /* error code */
        pushl   $19 /* vector */
        jmp     int_hand

__divide_error:
        pushl   $0 /* error code */
        pushl   $20 /* vector */
        jmp     int_hand
        .global __divide_error

int_hand:
        /* At this point on the stack there is:
         *  0(%esp) vector
         *  4(%esp) error code
         *  8(%esp) eip
         * 12(%esp) cs
         * 16(%esp) eflags
         */
        pushl   %edi
        pushl   %esi
        pushl   %ebp
        /* Original stack pointer */
        leal    32(%esp), %ebp
        pushl   %ebp
        pushl   %ebx
        pushl   %edx
        pushl   %ecx
        pushl   %eax

        pushl   %esp    /* Pointer to structure on the stack */

        call    x86_exception
        pop     %eax    /* Drop the pointer */

        popl    %eax
        popl    %ecx
        popl    %edx
        popl    %ebx
        popl    %ebp /* Ignore saved %esp value */
        popl    %ebp
        popl    %esi
        popl    %edi

        addl    $8, %esp /* pop of the vector and error code */

        iret

idtarg:
        .word   _idt_end - _idt - 1     /* limit */
        .long   _idt
        .word   0
_idt:
        .fill   20, 8, 0        # idt is unitiailzed
_idt_end:

        .globl  arch_nvram_size, arch_nvram_get, arch_nvram_put
arch_nvram_size:
        xor     %eax, %eax
        ret

arch_nvram_get:
        ret

arch_nvram_put:
        ret
