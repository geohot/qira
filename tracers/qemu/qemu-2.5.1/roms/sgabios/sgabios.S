/*
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sgabios.h"
#define BUILD_CL  "$Id$"

.code16
.text
  .section ".init","ax"
  .globl _start
  .type _start,@object
_start:
  /* option rom header */
  .byte 0x55
  .byte 0xaa
  .byte _rom_size_byte
  .size _start, .-_start

  .globl legacy_entry
  .type legacy_entry,@function
legacy_entry:
  jmp sga_init
  /* pnp entry here to avoid changing PnP table as code moves */
pnp_init:
  jmp pnp_sga_init

/*
 * do_old_int10h
 *
 * Patched at option rom init to be a far jump to old int 10h isr
 *
 */
do_old_int10h:
  .byte 0xea                           /* jmp absolute segment:offset */
old_int10h:                            /* store what was at offset 0x40 */
  .word 0xf065                         /* placeholder for chained ISR offset */
  /* if the chained segment is detected as 0xc000, use 80 cols only */
  /* since it's assumed that a vga card is attached and 80 cols max */
old_int10h_seg:
  .word 0xf000                         /* placeholder for chained ISR segment */
/*
 * do_old_int16h
 *
 * Patched at option rom init to be a far jump to old int 16h isr
 *
 */
do_old_int16h:
  .byte 0xea                           /* jmp absolute segment:offset */
old_int16h:                            /* store what was at offset 0x58 */
  .word 0xe82e                         /* placeholder for chained ISR offset */
  .word 0xf000                         /* placeholder for chained ISR segment */
.org 0x18
  .word 0                              /* offset to PCI data, 0 = none */
  .word pnp_table                      /* offset to PnP expansion header */
.org 0x20
pnp_table:
  /* FIXME: **** PnP header currently disabled by PoO **** */
  /* legacy entry only called once, PnP entry called multiple times */
  /* The code isn't yet written to deal with multiple inits properly */
  .ascii "$PoO"                        /* PnP expansion header signature */
  .byte 1                              /* structure revision */
  .byte 2                              /* length in 16-byte increments */
  .word 0                              /* offset of next header, 0 if none */
  .byte 0                              /* reserved */
  .byte 0x52                           /* checksum - update manually! FIXME */
  .long 0                              /* device identifier */
  .word mfg_string                     /* pointer to manufacturer string */
  .word prod_string                    /* pointer to product name string */
  .byte 3, 0x80, 0x80                  /* device type code = other display */
  .byte 0xe3                           /* device indicators, kbd/display dev */
  .word 0                              /* boot connection vector, 0 if none */
  .word 0                              /* disconnect vector, 0 if none */
  .word pnp_init                       /* bootstrap entry vector */
  .word 0                              /* reserved */
  .word 0                              /* static resource information vector */

  /* WARNING: changing mfg_string / prod_string locations will */
  /* affect pnp table above -- recalculate checksum manually! */
mfg_string:
  .asciz "Google, Inc."
prod_string:
  .ascii "Serial Graphics Adapter "
build_date:
  .asciz BUILD_SHORT_DATE
long_version:
  .ascii "SGABIOS "
  .ascii BUILD_CL
  .ascii " ("
  .ascii BUILD_USER
  .ascii "@"
  .ascii BUILD_HOST
  .ascii ") "
  .asciz BUILD_DATE
term_cols:
  .byte 80             /* overwritten at rom init with detected value */
term_rows:
  .byte 24             /* overwritten at rom init with detected value */
term_init_string:      /* terminal reply: \033[n;mR n=row, m=col */
  .asciz "\033[1;256r\033[256;256H\033[6n"
  /* reset the scroll, move to col 256, row 256, ask current position */
  /* bios cursor positions >255 rows or cols can't be used anyway */
term_info:
  .asciz "Term: "
ebda_info:
  .asciz "EBDA: "

/*
 * do_old_irq3 - exception 0x0b, int 0x0a
 *
 * Patched at option rom init to be a far jump to old irq 3 isr
 *
 */
do_old_irq3:
  .byte 0xea                           /* jmp absolute segment:offset */
old_irq3:          /* store what was at offset 0x28 */
  .word 0xeef3                         /* placeholder for chained ISR offset */
  .word 0xf000                         /* placeholder for chained ISR segment */

/*
 * do_old_irq4 - exception 0x0c, int 0x0b
 *
 * Patched at option rom init to be a far jump to old irq 4 isr
 *
 */
do_old_irq4:
  .byte 0xea                           /* jmp absolute segment:offset */
old_irq4:          /* store what was at offset 0x2c */
  .word 0xeef3                         /* placeholder for chained ISR offset */
  .word 0xf000                         /* placeholder for chained ISR segment */

/*
 * do_old_int14h
 *
 * Patched at option rom init to be a far jump to old int 14h isr
 *
 */
do_old_int14h:
  .byte 0xea                           /* jmp absolute segment:offset */
old_int14h:                            /* store what was at offset 0x50 */
  .word 0xe739                         /* placeholder for chained ISR offset */
  .word 0xf000                         /* placeholder for chained ISR segment */

.align 16, 0xff    /* aligning this table only makes hexdump prettier */
/* ascii -> scancode, bit 7=shifted, char < 32 = +ctrl */
/* except chars 8, 9, 13, 27 (bs, tab, enter, esc) */
/* most int16h consumers will probably never use */
ascii2scan:
/*00*/  .byte 0x00, 0x1e, 0x30, 0x2e, 0x20, 0x12, 0x21, 0x22
/*08*/  .byte 0x0e, 0x17, 0x24, 0x25, 0x26, 0x1c, 0x31, 0x18
/*10*/  .byte 0x19, 0x0f, 0x13, 0x1f, 0x14, 0x16, 0x2f, 0x11
/*18*/  .byte 0x2d, 0x15, 0x2c, 0x01, 0x2b, 0x1b, 0x87, 0x8c
/*20*/  .byte 0x39, 0x82, 0xa8, 0x84, 0x85, 0x86, 0x88, 0x28
/*28*/  .byte 0x8a, 0x8b, 0x89, 0x8d, 0x33, 0x0c, 0x34, 0x35
/*30*/  .byte 0x0b, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
/*38*/  .byte 0x09, 0x0a, 0xa7, 0x27, 0xb3, 0x0d, 0x34, 0xb5
/*40*/  .byte 0x83, 0x9e, 0xb0, 0xae, 0xa0, 0x92, 0xa1, 0xa2
/*48*/  .byte 0xa3, 0x97, 0xa4, 0xa5, 0xa6, 0xb2, 0xb1, 0x98
/*50*/  .byte 0x99, 0x90, 0x93, 0x9f, 0x94, 0x96, 0xaf, 0x91
/*58*/  .byte 0xad, 0x95, 0xac, 0x1a, 0x2b, 0x1b, 0x87, 0x8c
/*60*/  .byte 0x29, 0x1e, 0x30, 0x2e, 0x20, 0x12, 0x21, 0x22
/*68*/  .byte 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18
/*70*/  .byte 0x19, 0x10, 0x13, 0x1f, 0x14, 0x16, 0x2f, 0x11
/*78*/  .byte 0x2d, 0x15, 0x2c, 0x9a, 0xab, 0x9b, 0xa9, 0x0e

/* TABLES FOR NON-ASCII VGA CHARACTERS (CP437) TO ASCII */
/* Unicode at: http://en.wikipedia.org/wiki/Code_page_437 */

ctrl2ascii:
/* translate vga (CP437) first 32 characters to ascii */
/* for char 0, update the cursor position, but output nothing */
/* lilo uses this "trick" for a background attribute update */
  .ascii "\0@@v***........*><|!PS-|^v><L-^v"
high2ascii:
/* translate vga (CP437) chars 0x80 to 0xff to ascii */
/* these characters are mostly to visually approximate */
/* line art characters will probably need tweaking */
/*80*/  .ascii "CueaaaaceeeiiiAAEaAooouuyOUcLYPf"
/*a0*/  .ascii "aiounNao?--24!<>###||||++||+++++"
/*c0*/  .ascii "+--|-+||++--|-+----++++++++#-||-"
/*e0*/  .ascii "abgpesut00osiye^=+><||-=...vn2* "

colortable:
/* vga text color is IRGB, ansi color is BGR */
/* this table is effectively a nibble bit-reverse */
  .byte 0, 4, 2, 6, 1, 5, 3, 7

serial_port_base_address:
  .word COM_BASE_ADDR

/* in-memory console log
 *
 * It's expected that the EBDA contains a magic signature
 * like 0xdeadbabe, followed by a byte of flags, followed
 * by a 32-bit buffer pointer, followed by a 16-bit start
 * index, followed by a 16-bit end index, followed by 16-
 * bit logged character count, followed by an 8-bit flag.
 */

#define MEMCONSOLE_BUFFER_SIZE  32768
#define MEMCONSOLE_SIGNATURE  0xdeadbabe
#define MEMCONSOLE_ENDINDEX_OFF  0x0b
#define SGABIOS_EBDA_SIGNATURE  0x00414753

memconsole_buffer_start:               /* pulled from ebda struct */
  .long  0x00000000                    /* 0 = not found/no logging */
memconsole_ebda_deadbabe_offset:       /* bytes from start of ebda */
  .word  0x0000                        /* 40:0e contains ebda seg */
sgabios_ebda_logbuf_offset:            /* bytes from start of ebda */
  .word  0x0000                        /* 40:0e contains ebda seg */

/*
 * setup_memconsole
 *
 * Initialize the option rom variables associated with logging
 * of the legacy console output
 *
 * If these variables are left at zero, no logging will occur
 *
 * There are no parameters
 * All registers except flags should be preserved
 */

setup_memconsole:
  pushaw
  pushw %ds
  pushw %es
  pushw $BDA_SEG
  popw %ds                             /* ds = 0x40 */
  pushw BDA_EBDA                       /* push word at 0x0e */
  popw %es                             /* es = EBDA_SEG */
  /* search for memconsole signature in ebda */
  movl $MEMCONSOLE_SIGNATURE, %eax
  xorw %di, %di                        /* start at zero */
  movzbw %es:(%di), %cx                /* cx = size of EBDA in KB */
  shlw $8, %cx                         /* cx = (cx * 1024) / 4 */
  cld
  repnz
  scasl                                /* search until sig found */
  subw $4, %di                         /* scasl always increments di, undo */
  cmpl %eax, %es:(%di)                 /* is signature here? */
  jnz setup_memconsole_end             /* bail if so */
  movw %di, %cs:memconsole_ebda_deadbabe_offset  /* save offset */
  movl %es:5(%di), %eax                /* get 32-bit buffer base address */
  movl %eax, %cs:memconsole_buffer_start
setup_memconsole_end:
  popw %es
  popw %ds
  popaw
  ret

/*
 * memconsole_log_char
 *
 * Log the character passed in %al to the next available memory
 * console log position, if any.
 *
 * If memconsole_buffer_start is zero, no logging will occur
 *
 * %al = character to be logged
 * All registers except flags should be preserved
 */

memconsole_log_char:
  pushaw
  pushw %ds
  pushw %es
  pushw %fs
  pushw $BDA_SEG
  popw %ds                             /* ds = 0x40 */
  pushw BDA_EBDA                       /* push word at 0x0e */
  popw %es                             /* es = EBDA_SEG */
  movw %ax, %si                        /* %si = %al = byte to write */
  movl %cs:memconsole_buffer_start, %ebp
  movw %cs:memconsole_ebda_deadbabe_offset, %di
  addw $MEMCONSOLE_ENDINDEX_OFF, %di   /* %di points to char pos */
  orl %ebp, %ebp
  jz memconsole_log_tail               /* bufptr==0, no logging */
  movw %es:(%di), %bx                  /* bx = current position in buffer */
  cmpw $MEMCONSOLE_BUFFER_SIZE, %bx    /* at end of buffer? */
  jnc memconsole_log_tail              /* don't log any more if so */
  cmpb $0xd, %al                       /* is the char CR? */
  jz memconsole_log_tail               /* if so, ignore it */
  cmpb $0x8, %al                       /* is the char backspace? */
  jnz memconsole_update_fsbase         /* if not, log char as usual... */
  orw %bx, %bx                         /* make sure ptr isn't already zero */
  jz memconsole_log_tail               /* if so, bail */
  decw %bx                             /* else point to previous character */
  jmp memconsole_update_end_ptr        /* and go directly to save it */
memconsole_update_fsbase:
  movl $0xc0000100, %ecx               /* ecx = IA32_FS_BASE (AMD64+) */
  rdmsr                                /* read what was there before */
  pushl %eax                           /* save away previous FS_BASE eax */
  pushl %edx                           /* save away previous FS_BASE edx */
  xorl %edx, %edx                      /* clear high 32 bits */
  movl %ebp, %eax                      /* eax = memconsole buffer start */
  wrmsr                                /* fs_base = memconsole buffer start */
  movw %si, %ax                        /* %ax = saved value on entry */
  movb %al, %fs:(%bx)                  /* log character */
  popl %edx                            /* restore previous FS_BASE edx */
  popl %eax                            /* restore previous FS_BASE eax */
  wrmsr                                /* write what was there before */
  incw %bx                             /* update character count */
memconsole_update_end_ptr:
  movw %bx, %es:(%di)                  /* save new end pointer */
  addw $2, %di                         /* numchars stored at next word */
  movw %bx, %es:(%di)                  /* save new numchar value */
memconsole_log_tail:
  popw %fs
  popw %es
  popw %ds
  popaw
  ret

/* sgabioslog_setup_ebda
 *
 * SGABIOS makes its own 1KB EBDA allocation to save non-
 * translated characters with associated cursor positions
 * for the last 256 characters output.  This is organized
 * with 256 bytes reserved for houskeeping, 256 bytes for
 * the raw character codes, and 512 bytes of 16bit cursor
 * positions to record the associated position for each.
 *
 * The first 4 bytes contain "SGA\0" followed by a 16-bit
 * size of the allocation in bytes,  followed by a 16-bit
 * index indicating the next spot to be overwritten.
 * 
 * There are no parameters
 * All registers should be preserved
 */

sgabioslog_setup_ebda:
  pushf
  pushaw
  pushw %ds
  pushw %es
  pushw $BDA_SEG
  popw %ds                             /* ds = 0x40 */
  movw BDA_EBDA, %ax                   /* ax = old ebda segment from 0x0e */
  subw $SGABIOS_EBDA_DELTA, %ax
  movw %ax, %es                        /* es = new EBDA segment start */
  cmpw $EBDA_MIN_SEG, %ax              /* is there room for the allocation? */
  jc sgabioslog_setup_ebda_tail        /* if not, don't change anything */
  cli                                  /* paranoid in case irq uses EBDA */
  movw %ax, BDA_EBDA                   /* save new EBDA segment start */
  subw $SGABIOS_EBDA_KB, BDA_MEM_SIZE  /* subtract extra allocation */
  movw %ax, %ds                        /* ds = new EBDA segment start */
  movw $SGABIOS_EBDA_BYTES, %si        /* si = offset of first byte to move */
  movzbw (%si), %cx                    /* cx = number of KB in EBDA */
  addb $SGABIOS_EBDA_KB, (%si)         /* update EBDA size in kb */
  shlw $10, %cx                        /* cx = KB * 1024 = bytes in EBDA */
  movw %cx, %cs:sgabios_ebda_logbuf_offset  /* new ebda space */
  xorw %di, %di                        /* di = new EBDA start */
  cld
  rep
  movsb                                /* move ebda by SGABIOS_EBDA_BYTES */
  movw %cs:sgabios_ebda_logbuf_offset, %bx  /* bx = new buffer */
  movl $SGABIOS_EBDA_SIGNATURE, (%bx)  /* setup signature */
  movw $SGABIOS_EBDA_BYTES, 4(%bx)     /* bytes in new ebda buffer */
  movw $0, 6(%bx)                      /* next log index, new ebda buffer */
sgabioslog_setup_ebda_tail:
  popw %es
  popw %ds
  popaw
  popf
  ret

/*
 * sgabioslog_save_char
 *
 * Like memconsole_log_char, except the original, untranslated
 * character is expected to be given in the %al register.
 *
 * The original character and its corresponding cursor position
 * are logged to the sgabios ebda memory allocation.
 *
 * %al = character to be logged
 * All registers except flags should be preserved
 */

sgabioslog_save_char:
  pushaw
  pushw %ds
  pushw %es
  pushw $BDA_SEG
  popw %ds                             /* ds = 0x40 */
  pushw BDA_EBDA                       /* push word at 0x0e */
  popw %es                             /* es = EBDA_SEG */
  movw %cs:sgabios_ebda_logbuf_offset, %di
  orw %di, %di                         /* is offset zero? */
  jz sgabioslog_save_tail              /* if so, bail */
  cmpl $SGABIOS_EBDA_SIGNATURE, %es:(%di)
  jnz sgabioslog_save_tail             /* bail if magic not found */
  movw %es:6(%di), %bx                 /* bx = index of next char output */
  movb %al, %es:SGABIOS_EBDA_LOG_START(%bx,%di)  /* store character */
  movzbw %bl, %ax                      /* %ax = next cursor buffer index */
  shlw $1, %ax                         /* %ax = offset to cursor storage */
  call get_current_cursor              /* %dh = row, %dl = column */
  addw $SGABIOS_EBDA_POS_START, %di    /* cursor storage */
  addw %ax, %di                        /* %di = next cursor storage offset */
  movw %dx, %es:(%di)                  /* save position for logged char */
  incw %bx                             /* point to next char to log */
  cmpw $SGABIOS_EBDA_LOG_SIZE, %bx
  jnz sgabioslog_save_index
  xorw %bx, %bx                        /* wrap around to start */
sgabioslog_save_index:
  movw %cs:sgabios_ebda_logbuf_offset, %di
  movw %bx, %es:6(%di)                 /* save new index */
sgabioslog_save_tail:
  popw %es
  popw %ds
  popaw
  ret

/*
 * sgabioslog_get_char
 *
 * Return the character at current cursor position, last recorded
 * to sgabios ebda allocation, if available.
 *
 * If the current cursor postition contains one of the last 256 characters
 * written to the ebda buffer, return that character, else return 0.
 *
 * If sgabios_ebdda_logbuf_offset is zero, %al will be 0 and zf set
 *
 * All registers except flags and %al should be preserved
 */

sgabioslog_get_char:
  pushaw
  movw %sp, %bp
  movb $0, 14(%bp)                     /* %al on stack = 0 */
  pushw %ds
  pushw %es
  pushw $BDA_SEG
  popw %ds                             /* ds = 0x40 */
  pushw BDA_EBDA                       /* push word at 0x0e */
  popw %es                             /* es = EBDA_SEG */
  movw %cs:sgabios_ebda_logbuf_offset, %di
  orw %di, %di
  jz sgabioslog_get_tail               /* offset==0, no logging */
  cmpl $SGABIOS_EBDA_SIGNATURE, %es:(%di)
  jnz sgabioslog_get_tail              /* bail if magic not found */
  call get_current_cursor              /* dh = row, dl = col */
  std                                  /* scan backwards in mem */
  movw %es:6(%di), %bx                 /* bx = index of next char output */
  decw %bx                             /* %bx = offset of last char in buf */
  jnc sgabioslog_got_pos
  addw $SGABIOS_EBDA_LOG_SIZE, %bx     /* bx position wrap around */
sgabioslog_got_pos:
  movw %bx, %ax                        /* %ax = last cursor pos written */
  shlw $1, %ax                         /* %ax = offset of last cursor pos */
  addw $SGABIOS_EBDA_POS_START, %di    /* %di = first cursor position */
  addw %ax, %di                        /* %di = offset in ebda */
  movw %dx, %ax                        /* %ax = cursor pos to compare */
  movw %bx, %cx                        /* %cx = positions before wrap */
  jcxz sgabioslog_cmp_wrap             /* if zero, try from end next */
  repnz
  scasw                                /* search until position match */
  addw $2, %di                         /* scasd always decrements di, undo */
  cmpw %ax, %es:(%di)                  /* did it really match? */
  jz sgabioslog_cursor_match           /* if so, do something */
sgabioslog_cmp_wrap:
  movw %cs:sgabios_ebda_logbuf_offset, %di
  addw $SGABIOS_EBDA_POS_LAST, %di     /* %di = last cursor storage */
  movw $SGABIOS_EBDA_LOG_SIZE, %cx     /* %cx = compare all positions */
  repnz
  scasw                                /* search until position match */
  addw $2, %di                         /* scasd always decrements di, undo */
  cmpw %ax, %es:(%di)                  /* did it really match? */
  jnz sgabioslog_get_tail              /* if not, bail */
sgabioslog_cursor_match:
  /* %di contains the EBDA offset of the matching position */
  /* convert this into a memconsole offset */
  subw $512, %di                       /* take off the storage offset */
  subw %cs:sgabios_ebda_logbuf_offset, %di  /* and ebda offset */
  shrw $1, %di                         /* %di = char position index */
  addw %cs:sgabios_ebda_logbuf_offset, %di  /* add back ebda offset */
  addw $SGABIOS_EBDA_LOG_START, %di    /* and add back log offset */
  movb %es:(%di), %al                  /* get related saved character */
  movb %al, 14(%bp)                    /* %al on stack = logged char */
sgabioslog_get_tail:
  popw %es
  popw %ds
  popaw
  ret

/*
 * multibyteinput
 *
 * When an escape key is detected, the input routines will attempt to
 * capture as many characters as arrive up until a timeout, or six,
 * whichever is less.
 *
 * This table is intended to decide what the characters after the
 * initial escape key translate to in terms of high and low bytes
 * that go into the keyboard buffer the high byte is the scancode,
 * the low byte is ascii, but for special keys this is usually 0xe0
 * or 0x00.
 *
 * This table is formatted so that the first word is a scancode +
 * ascii pair (as returned by int 16h, ah = 10h or 11h).  Immediately
 * following is a nul-terminated ascii string to match in order to
 * use the corresponding scancode+ascii word.
 *
 * The search through this table is terminated by a match or finding
 * a 0 scancode+ascii word.
 *
 * FIXME: all the low bytes are now zero, get rid of them?
 */
multibyteinput:
  .byte 0x3b                           /* F1 */
  .asciz "[[A"                         /* F1/screen */

  .byte 0x3b                           /* F1 */
  .asciz "OP"                          /* F1/xterm/ansi */

  .byte 0x3b                           /* F1 */
  .asciz "[11~"                        /* F1/vt400 */

  .byte 0x3c                           /* F2 */
  .asciz "[[B"                         /* F2/screen */

  .byte 0x3c                           /* F2 */
  .asciz "OQ"                          /* F2/xterm/ansi */

  .byte 0x3c                           /* F2 */
  .asciz "[12~"                        /* F2/vt400 */

  .byte 0x3d                           /* F3 */
  .asciz "[[C"                         /* F3/screen */

  .byte 0x3d                           /* F3 */
  .asciz "OR"                          /* F3/xterm/ansi */

  .byte 0x3d                           /* F3 */
  .asciz "[13~"                        /* F3/vt400 */

  .byte 0x3e                           /* F4 */
  .asciz "[[D"                         /* F4/screen */

  .byte 0x3e                           /* F4 */
  .asciz "OS"                          /* F4/xterm/ansi */

  .byte 0x3e                           /* F4 */
  .asciz "[14~"                        /* F4/vt400 */

  .byte 0x3f                           /* F5 */
  .asciz "[[E"                         /* F5/screen */

  .byte 0x3f                           /* F5 */
  .asciz "[15~"                        /* F5/xterm */

  .byte 0x3f                           /* F5 */
  .asciz "OT"                          /* F5/ansi */

  .byte 0x40                           /* F6 */
  .asciz "[17~"                        /* F6/screen/vt220/xterm/vt400 */

  .byte 0x40                           /* F6 */
  .asciz "OU"                          /* F6/ansi */

  .byte 0x41                           /* F7 */
  .asciz "[18~"                        /* F7/screen/vt220/xterm/vt400 */

  .byte 0x41                           /* F7 */
  .asciz "OV"                          /* F7/ansi */

  .byte 0x42                           /* F8 */
  .asciz "[19~"                        /* F8/screen/vt220/xterm/vt400 */

  .byte 0x42                           /* F8 */
  .asciz "OW"                          /* F8/ansi */

  .byte 0x43                           /* F9 */
  .asciz "[20~"                        /* F9/screen/vt220/xterm/vt400 */

  .byte 0x43                           /* F9 */
  .asciz "OX"                          /* F9/ansi */

  .byte 0x44                           /* F10 */
  .asciz "[21~"                        /* F10/screen/vt220/xterm/vt400 */

  .byte 0x44                           /* F10 */
  .asciz "OY"                          /* F10/ansi */

  .byte 0x85                           /* F11 */
  .asciz "[23~"                        /* F11/screen/xterm/vt400 */

  .byte 0x85                           /* F11 */
  .asciz "OZ"                          /* F11/ansi */

  .byte 0x86                           /* F12 */
  .asciz "[24~"                        /* F12/screen/xterm/vt400 */

  .byte 0x52                           /* Insert */
  .asciz "[2~"                         /* Insert/screen/vt102/xterm */

  .byte 0x53                           /* Delete */
  .asciz "[3~"                         /* Delete/screen/vt102/xterm */

  .byte 0x4b                           /* Left */
  .asciz "OD"                          /* Left/screen/vt102 */

  .byte 0x4b                           /* Left */
  .asciz "[D"                          /* Left/xterm */

  .byte 0x47                           /* Home */
  .asciz "[1~"                         /* Home/screen/vt102 */

  .byte 0x47                           /* Home */
  .asciz "[H"                          /* Home/xterm */

  .byte 0x4f                           /* End */
  .asciz "[4~"                         /* End/screen/vt102 */

  .byte 0x4f                           /* End */
  .asciz "[F"                          /* End/xterm */

  .byte 0x48                           /* Up */
  .asciz "OA"                          /* Up/screen/vt102 app */

  .byte 0x48                           /* Up */
  .asciz "[A"                          /* Up/xterm/vt102 ansi */

  .byte 0x50                           /* Down */
  .asciz "OB"                          /* Down/screen/vt102 app */

  .byte 0x50                           /* Down */
  .asciz "[B"                          /* Down/xterm/vt102 ansi */

  .byte 0x49                           /* PageUp */
  .asciz "[5~"                         /* PageUp/screen/vt102/xterm */

  .byte 0x51                           /* PageDown */
  .asciz "[6~"                         /* PageDown/screen/vt102/xterm */

  .byte 0x4d                           /* Right */
  .asciz "OC"                          /* Right/screen/vt102 app */

  .byte 0x4d                           /* Right */
  .asciz "[C"                          /* Right/xterm/vt102 ansi */

  .byte 0                              /* end of table marker */

/* init_serial_port
 *
 * Initialize serial port to 115200,8n1
 * Serial interrupts disabled
 *
 * All registers except flags preserved
 */

init_serial_port:
  pushw %ax
  pushw %dx
  pushw %bx
  movw %cs:serial_port_base_address, %dx
  addw $IER_OFFSET, %dx
  xorb %al, %al
  outb %al, %dx                        /* disable all serial interrupts */
  addw $(LCR_OFFSET - IER_OFFSET), %dx /* LCR */
  movb $(LCR_VALUE|LCR_DLAB), %al
  outb %al, %dx                        /* enable divisor access */
  movw %cs:serial_port_base_address, %dx
  movw $(PORT_DIVISOR/PORT_SPEED), %bx
  movb %bl, %al                        /* al = lsb of divisor */
  outb %al, %dx                        /* set divisor latch lsb */
  movb %bh, %al                        /* al = msb of divisor */
  incw %dx
  outb %al, %dx                        /* set divisor latch msb */
  movw %cs:serial_port_base_address, %dx
  addw $LCR_OFFSET, %dx
  movb $LCR_VALUE, %al
  outb %al, %dx                        /* disable divisor access */
  addw $(MCR_OFFSET - LCR_OFFSET), %dx /* MCR */
  movb $MCR_DTRRTS, %al
  outb %al, %dx                        /* enable DTR + RTS */
  movw %cs:serial_port_base_address, %dx
  addw $FCR_OFFSET, %dx
  movb $FCR_FIFO_ENABLE, %al
  outb %al, %dx                        /* enable FIFOs */
  popw %bx
  popw %dx
  popw %ax
  ret


/* get_serial_lsr
 *
 * return serial line status register in %al
 * return offset to serial port line status register io port in %dx
 * all other registers except flags unchanged
 *
 * if status == 0xff  return ZF=1, else return ZF=0
 */

get_serial_lsr:
  movw %cs:serial_port_base_address, %dx
  addw $LSR_OFFSET, %dx
  inb %dx, %al
  cmpb $0xff, %al
  ret
  
/*
 * get_byte
 *
 * get serial byte in %al, scancode in %ah [FIXME: EFI console input]
 *
 * all registers except %ax preserved
 *
 */

get_byte:
  pushw %dx
  pushw %bx
next_serial_char:
  call get_serial_lsr                  /* get serial lsr in %al */
  jz get_byte_tail                     /* no port present... */
  testb $1, %al                        /* bit 0 of LSR = 1 = data available */
  jz get_byte_tail                     /* no input waiting */
  /* new character found on serial port */
  /* convert it to a scancode */
  movw %cs:serial_port_base_address, %dx
  inb %dx, %al                         /* al = serial input char */
  testb $0x80, %al                     /* non-ascii char received? */
  jnz next_serial_char                 /* throw char away */
  movb %al, %dl                        /* dl = character read */
  pushw %ds
  pushw %cs
  popw %ds                             /* ds = cs */
  movw $ascii2scan, %bx                /* table to translate ascii->scan */
  xlatb                                /* translate char to scancode */
  popw %ds
  /* shift status is ignored at this point, may be used later */
  andb $0x7f, %al                      /* strip shift status from table */
  movb %al, %ah                        /* scancode goes in high byte */
  movb %dl, %al                        /* "translated" ascii in lower byte */
  cmpb $0x7f, %al                      /* Did the user transmit ascii DEL? */
  jnz get_byte_not_del                 /* if not, don't do anything to al */
  movb $0x08, %al                      /* else delete becomes backspace */
get_byte_not_del:
  testw %ax, %ax                       /* clear zero flag */
get_byte_tail:
  popw %bx
  popw %dx
  ret

/*
 * poll_byte
 *
 * get serial byte in %al, scancode in %ah [FIXME: EFI console input]
 * retry up to 65536 times for an expected input byte
 *
 * all registers except %ax preserved
 *
 */

poll_byte:
  pushw %cx
  xorw %cx, %cx
poll_byte_retry:
  inb $0xed, %al
  call get_byte
  loopz poll_byte_retry                /* repeat while zf set or cx != 0 */
  popw %cx
  ret

/*
 * get_multibyte
 *
 * after an escape character, poll for terminal keys that generate
 * an escape code plus multiple bytes (up to four).
 *
 * if no byte is waiting, all registers preserved except flags
 * if more bytes are waiting, all registers preserved except %ax and flags
 *
 */
get_multibyte:
  pushw %bp                            /* bp points to temp buffer on stack */
  pushw %bx                            /* bx points to multibyteinput table */
  pushw %cx                            /* cx will count chars */
  pushw %ax                            /* ax will receive chars */
  pushl $0                             /* make space on stack for 4 chars */
  xorw %cx, %cx                        /* cx = 0 */
  movw %sp, %bp                        /* point bp at temp data */
  call poll_byte                       /* is a character waiting? */
  jz get_multibyte_tail                /* if not, bail */
get_multibyte_store:
  movb %al, (%bp)                      /* store char received */
  incb %cl                             /* mark one char received */
  incw %bp                             /* point to next char */
  cmpb $4, %cl                         /* got enough chars? */
  jz got_multibyte                     /* no strings longer than 4 chars */
  call poll_byte                       /* is another char waiting? */
  jnz get_multibyte_store              /* store a new one if it's there */
got_multibyte:
  movw $multibyteinput, %bx            /* point to first scancode */
got_multibyte_findkey:
  movw %sp, %bp                        /* bp = start of buffer */
  movb %cs:(%bx), %ah                  /* ah = scancode */
  incw %bx                             /* bx = start of test string */
  orb %ah, %ah                         /* is it zero? */
  jz get_multibyte_tail                /* if so, bail, key not found */
got_multibyte_nextchar:
  movb %cs:(%bx), %ch                  /* ch = test char to compare */
  incw %bx                             /* point to next char */
  orb %ch, %ch                         /* is char to compare NUL? */
  jz got_multibyte_key                 /* matched to end of a string! */
  cmpb %ch, (%bp)                      /* input tmp buf equal to test char? */
  jnz got_multibyte_try_next_key
  /* note: expected that test string will be nul before input string */
  /* no attempt is made to ensure no more than 4 bytes stack read */
  incw %bp                             /* point to next input */
  jmp got_multibyte_nextchar
got_multibyte_try_next_key:  /* align to next scancode/ascii pair */
  movb %cs:(%bx), %ch                  /* ch = test char to compare */
  incw %bx                             /* point to next char */
  orb %ch, %ch                         /* is char to compare NUL? */
  jnz got_multibyte_try_next_key
  jmp got_multibyte_findkey
got_multibyte_key:
  xorb %al, %al                        /* ascii value = 0 for special keys */
  movw %sp, %bp
  movw %ax, 4(%bp)                     /* overwrite old %ax value with key */
get_multibyte_tail:
  addw $4, %sp                         /* pop temp space */
  popw %ax
  popw %cx
  popw %bx
  popw %bp
  ret

/*
 * send_byte
 *
 * send character in %al to serial port [FIXME: EFI console out]
 *
 * all registers preserved except flags
 *
 */

send_byte:
  pushw %ax
  pushw %dx
  pushw %cx
  testb $0x80, %al                     /* don't send non-ascii chars */
  jnz send_tail                        /* these should be translated earlier */
  movb %al, %ah                        /* save char to output in %ah */
  movw $0xFFF0, %cx                    /* only retry 65520 times */
serial_ready_test:
  call get_serial_lsr                  /* get serial lsr in %al */
  testb $TRANSMIT_READY_BIT, %al
  loopz serial_ready_test              /* if !tx ready, loop while cx!=0 */
  movb %ah, %al
  movw %cs:serial_port_base_address, %dx
  outb %al, %dx
send_tail:
  popw %cx
  popw %dx
  popw %ax
  ret

/*
 * translate_char
 *
 * translate vga character in %al to ascii
 *
 * returns:
 * al = translated character
 *
 * all registers except %al preserved
 *
 */

translate_char:
  pushw %bx
  pushw %ds
  pushw %cs
  popw %ds                             /* ds = cs */
  testb $0x80, %al
  jz translate_char_ctrl
  andb $0x7f, %al
  movw $high2ascii, %bx
  xlatb
translate_char_ctrl:
  cmpb $0x20, %al
  jnc translate_char_tail
  movw $ctrl2ascii, %bx
  xlatb
translate_char_tail:
  popw %ds
  popw %bx
  ret

/*
 * translate_char_tty
 *
 * translate vga character in %al to ascii
 * unless %al == 7, 8, 10, or 13 (bell, bs, lf, cr)
 *
 * returns:
 * al = translated character
 *
 * all registers except %al preserved
 *
 */

translate_char_tty:
  cmpb $0x07, %al                      /* bell */
  jz translate_char_tty_tail
  cmpb $0x08, %al                      /* backspace */
  jz translate_char_tty_tail
  cmpb $0x0a, %al                      /* LF */
  jz translate_char_tty_tail
  cmpb $0x0d, %al                      /* CR */
  jz translate_char_tty_tail
  call translate_char
translate_char_tty_tail:
  ret

/*
 * send_char
 *
 * send character 0 - 255 in %al out through serial port
 * increment cursor position without control processing
 *
 * send_byte is used for data that isn't tracked
 *
 * send_char is used for text that should be tracked
 * send_char outputs all characters as non-control chars
 *
 * returns:
 * al = translated character
 *
 * all registers except %al preserved
 *
 */

send_char:
  call sgabioslog_save_char            /* save original char+pos */
  call translate_char
  jmp send_char_tty_out
  /* after ctrl translation, same as send_char_tty */

/*
 * send_char_tty
 *
 * send character 0 - 255 in %al out through serial port
 * increment cursor position *with* control processing
 * for bell, linefeed, cr, and backspace (others all printable)
 *
 * send_byte is used for data that isn't tracked
 *
 * send_char_tty is used for text that should be tracked
 *
 * returns:
 * al = translated character
 *
 * all registers except %al preserved
 *
 */


/* send character 0 - 255 in %al out through serial port */
/* increment cursor position with CR/LF/Backspace processing */
send_char_tty:
  call sgabioslog_save_char            /* save original char+pos */
  call translate_char_tty
send_char_tty_out:
  pushw %dx
  call update_serial_cursor
  call get_current_cursor              /* vga cursor in %dx */
  cmpb $0x0d, %al                      /* CR */
  jnz send_char_tty_nul                /* if not CR, check for NUL */
  orb %dl, %dl                         /* already at col 0? */
  jz send_char_tty_tail                /* no need to re-send CR */
send_char_tty_nul:
  orb %al, %al                         /* %al == 0 ? (nul) */
  /* more than likely, we have NUL at this point because the caller */
  /* tried to read a char using int $0x10, %ah=8, and is trying */
  /* to re-output it with different attributes - for now send nothing */
  jz send_char_tty_tail
send_char_tty_write:
  call memconsole_log_char             /* log character sent */
  call send_byte
  cmpb $0x07, %al                      /* bell */
  jz send_char_tty_tail                /* no cursor update for bell */
  cmpb $0x08, %al                      /* backspace */
  jz send_char_tty_backspace
  cmpb $0x0a, %al                      /* LF */
  jz send_char_tty_lf
  cmpb $0x0d, %al                      /* CR */
  jz send_char_tty_cr
  incb %dl
  jmp send_char_tty_tail
send_char_tty_backspace:
  orb %dl, %dl
  jz send_char_tty_tail
  decb %dl
  jmp send_char_tty_tail
send_char_tty_lf:
  incb %dh
  jmp send_char_tty_tail
send_char_tty_cr:
  xorb %dl, %dl
send_char_tty_tail:
  cmpb %cs:term_cols, %dl
  jc send_char_tty_check_rows
  movb %cs:term_cols, %dl
  decb %dl                             /* dl = cols - 1 */
send_char_tty_check_rows:
  cmpb %cs:term_rows, %dh
  jc send_char_tty_save_cursor
  movb %cs:term_rows, %dh
  decb %dh                             /* dh = rows - 1 */
send_char_tty_save_cursor:
  call set_current_cursor
  pushw %ds
  pushw $BDA_SEG
  popw %ds
  /* save current position as the serial terminal position */
  /* since a character was just output at that position */
  movw %dx, BDA_SERIAL_POS
  popw %ds
  popw %dx
  ret

/*
 * send_asciz_out
 *
 * send nul terminated string pointed to by %ds:%si
 * to serial port without text tracking
 *
 * indended to be used for multi-byte send_byte
 *
 * all registers preserved except flags
 */

send_asciz_out:
  pushw %ax
  pushw %si
  cld
send_asciz_loop:
  lodsb
  test %al,%al
  jz send_asciz_end
  call send_byte
  jmp send_asciz_loop
send_asciz_end:
  popw %si
  popw %ax
  ret

/*
 * send_string
 *
 * send cx chars in string pointed to by %ds:%si
 * to serial port with tty tracking
 * 
 * indended to be used for multi-byte send_char_tty
 *
 * all registers preserved except flags
 */

send_string:
  pushw %ax
  pushw %si
  cld
send_string_loop:
  lodsb
  call send_char_tty
  loop send_string_loop
  popw %si
  popw %ax
  ret

/*
 * send_string
 *
 * send cx chars in string pointed to by %ds:%si
 * with interleaved attribute data
 * 
 * indended to be used for multi-byte send_char_tty
 * with interleaved vga attribute updates
 *
 * all registers preserved except flags
 */

send_attr_string:
  pushw %ax
  pushw %bx
  pushw %si
  cld
send_attr_string_loop:
  lodsb
  call send_char_tty
  lodsb
  movb %al, %bl
  call send_attribute                  /* send attribute in %bl */
  loop send_attr_string_loop
  popw %si
  popw %bx
  popw %ax
  ret

/*
 * send_number
 *
 * send ascii version of number in %al to serial port
 * 
 * intended for ansi cursor positions and attributes,
 * so cursor position is not tracked/updated
 *
 * all registers preserved except flags
 */

send_number:
  pushw %ax
  pushw %bx
  aam                                  /* ah = al/10, al = al mod 10 */
  movw %ax, %bx                        /* bh = al/10, bl = al mod 10 */
  movb %bh, %al
  aam                                  /* ah = bh/10, al = bh mod 10 */
  movb %al, %bh                        /* bh = 10s digit, bl = 1s digit */
  movb %ah, %al                        /* ah = al = 100s digit */
  testb %al, %al                       /* is there a 100s digit? */
  jz send_tens                         /* move to tens if not */
  orb $0x30, %al                       /* al = ascii value of digit */
  call send_byte
send_tens:
  orb %bh, %ah                         /* bh = 10s, ah = 100s digits */
  jz send_ones                         /* non-zero = must send tens */
  movb %bh, %al                        /* al = bh = 10s digit */
  orb $0x30, %al                       /* al = ascii value of digit */
  call send_byte
send_ones:
  movb %bl, %al                        /* al = bl = 1s digit */
  orb $0x30, %al                       /* al = ascii value of digit */
  call send_byte
  popw %bx
  popw %ax
  ret

/*
 * send_crlf
 *
 * send CRLF to serial port
 * 
 * FIXME: used at vga init and for scrolling terminal
 * so position is not tracked.  Callers of this routine
 * predate the code that does smart tty/cursor output.
 *
 * Callers should probably be changed to use those
 * routines or send_crlf changed to use them and
 * terminal scrolling fixed to use linefeed only.
 *
 * all registers preserved except flags
 */

send_crlf:
  pushw %ax
  movb $0x0d, %al
  call send_byte
  movb $0x0a, %al
  call send_byte
  popw %ax
  ret
/*
 * send_ansi_csi
 *
 * send ESCAPE [ to serial port
 * 
 * output is not tracked since these are control sequences
 *
 * all registers preserved except flags
 */

send_ansi_csi:      /* transmit ESC [ */
  pushw %ax
  movb $0x1b, %al                      /* escape */
  call send_byte
  movb $0x5b, %al                      /* [ */
  call send_byte
  popw %ax
  ret
/*
 * send_ansi_csi_2num
 *
 * send ESC [ %dh ; %dl to serial port
 * 
 * since both position and attribute updates generally have
 * two parameters, this function converts values in dx to
 * two ascii numbers.  It's expected that the caller will
 * output the final trailing H or m or whatever is required.
 *
 * output is not tracked since these are control sequences
 *
 * all registers preserved except flags
 */

send_ansi_csi_2num:
/* send ESC [ %dh ; %dl */
  pushw %ax
  call send_ansi_csi                   /* esc [ */
  movb %dh, %al
  call send_number
  movb $0x3b, %al                      /* semicolon */
  call send_byte
  movb %dl, %al
  call send_number
  popw %ax
  ret

/*
 * send_ansi_cursor_pos
 *
 * send ESC [ %dh+1 ; %dl+1 to serial port to position
 * cursor
 * 
 * since both position and attribute updates generally have
 * two parameters, this function converts values in dx to
 * two ascii numbers, after adding 1 to both dh and dl.
 *
 * output is not tracked since this is a control sequence
 *
 * all registers preserved except flags
 */

send_ansi_cursor_pos:
  pushw %ax
  pushw %dx
  addw $0x0101, %dx                    /* dh += 1, dl += 1 */
  call send_ansi_csi_2num              /* send esc [ %dh+1;%dl+1 */
  movb $0x48, %al                      /* H */
  call send_byte
  popw %dx
  popw %ax
  ret

/*
 * send_attribute
 *
 * send ansi attribute change ESC [ 4x ; 3y ; (1|22)m
 * if the attribute has changed since last sent (stored in bda)
 * 
 * output is not tracked since this is a control sequence
 *
 * all registers preserved except flags
 */

send_attribute:
  andb $0x7f, %bl                      /* ansi has no bright bg */
  pushw %ds
  pushw %es
  pushw %ax
  pushw %bx
  pushw %dx
  pushw $BDA_SEG
  popw %es                             /* es = 0x40 */
  pushw %cs
  popw %ds                             /* ds = cs */
  cmpb %es:BDA_COLOR_VAL, %bl
  jz send_attribute_tail
  cmpb $0x07, %bl                      /* is it white on black? */
  jnz send_attribute_color
  /* for white on black, send esc [ m */
  call send_ansi_csi
  jmp send_attribute_m                 /* send the m, return */
send_attribute_color:
  movb %bl, %ah                        /* ah = attribute */
  movw $colortable, %bx
  movb %ah, %al
  andb $7, %al                         /* al = fg attr */
  xlatb                                /* al = fg ansi num */
  movb %al, %dl                        /* dl = fg ansi num */
  movb %ah, %al
  shrb $4, %al                         /* al = bg attr */
  xlatb                                /* al = bg ansi num */
  movb %al, %dh                        /* dh = bg ansi num */
  addw $0x281e, %dx                    /* 3x=setfg, 4x=setbg */
  call send_ansi_csi_2num
  movb $0x3b, %al                      /* semicolon */
  call send_byte
  shlb $4, %ah                         /* bright text? */
  sets %al                             /* if bit 7, al = 1 */
  js send_attribute_intensity
  movb $22, %al                        /* 22 = normal intensity */
send_attribute_intensity:
  call send_number                     /* either 22 or 1 */
send_attribute_m:
  movb $0x6d, %al                      /* m */
  call send_byte
send_attribute_tail:
  popw %dx
  popw %bx
  /* mark attribute in %bl the current one */
  movb %bl, %es:BDA_COLOR_VAL
  popw %ax
  popw %es
  popw %ds
  ret

/*
 * serial_get_input
 *
 * common code for both interrupt-driven and non-interrupt
 * driven serial input.   Called only when LSR bit 1 is set.
 *
 * No parameters, no return values
 *
 * Preserves all registers
 */

serial_get_input:
  pushf
  /* be paranoid about int 9h happening during update */
  cli
  pushaw
  pushw %ds
  /* next char input buffer is at 0x40:0x1c */
  pushw $BDA_SEG
  popw %ds                             /* es = 0x40 */
  call get_byte                        /* next scancode/byte in %ax */
  cmpb $0x1b, %al                      /* look for escape */
  jnz serial_gotkey                    /* not escape, don't look for more bytes */
  call get_multibyte                   /* look for any chars after escape */
serial_gotkey:
  movw KBD_TAIL, %bx                   /* bx = keyboard tail pointer */
  movw %ax, (%bx)                      /* store key in buffer */
  addw $2, %bx                         /* point to next location */
  cmpw $KBD_BUF_END, %bx               /* did the buffer wrap? */
  jb kbd_buf_no_wrap
  movw $KBD_BUF_START, %bx
kbd_buf_no_wrap:
  movw %bx, KBD_TAIL                   /* update tail pointer to show key */
  popw %ds
  popaw
  popf
  ret

/*
 * irq3_isr
 *
 * entry point for irq 3 / int 0x0b / exception 11
 *
 * Called when COM2 or COM4 have characters pending
 *
 * The segment not present exception should never happen
 * in real mode 16-bit code like this, but just to be safe,
 * if this interrupt is invoked and no characters are
 * pending on the port found in serial_port_base_address,
 * this routine will chain to the original handler.
 *
 * If characters are found pending, they will be processed
 * and control returned via iret.
 */

irq3_isr:
#if 0
  pushw %ax
  pushw %dx
  /* placeholder, this shouldn't ever happen */
  /* no interrupts are configured outside COM1 */
  call get_serial_lsr                  /* get serial lsr in %al */
  jz chain_irq3                        /* no port present... */
  testb $1, %al                        /* bit 0 of LSR = 1 = data available */
  jz chain_irq3                        /* no input waiting */
  call serial_get_input                /* get input and stuff kbd buffer */
  movb $0x20, %al
  outb %al, $0x20                      /* send non-specific EOI */
  popw %dx
  popw %ax
  iret
chain_irq3:
  popw %dx
  popw %ax
#endif
  jmp do_old_irq3

/*
 * irq4_isr
 *
 * entry point for irq 4 / int 0x0c / exception 12
 *
 * Called when COM1 or COM3 have characters pending
 *
 * The stack fault exception may occur if code attempts to
 * read from sp:0xffff, so if this interrupt is invoked and
 * no characters are pending on the port found in
 * serial_port_base_address, this routine will chain to the
 * original handler.
 *
 * If characters are found pending, they will be processed
 * and control returned via iret.
 */

irq4_isr:
#if 0
  pushw %ax
  pushw %dx
  call get_serial_lsr                  /* get serial lsr in %al */
  jz chain_irq4                        /* no port present... */
  testb $1, %al                        /* bit 0 of LSR = 1 = data available */
  jz chain_irq4                        /* no input waiting */
  call serial_get_input                /* get input and stuff kbd buffer */
  movb $0x20, %al
  outb %al, $0x20                      /* send non-specific EOI */
  popw %dx
  popw %ax
  iret
chain_irq4:
  popw %dx
  popw %ax
#endif
  jmp do_old_irq4

/*
 * int14h_isr
 *
 * entry point for int 14h
 *
 */
int14h_isr:
  pushaw
  movw %sp, %bp
  addw $16, %bp                        /* bp points to return address */
  orb %ah, %ah                         /* fn 0x00, initialize port */
  jz int14h_init_port
  cmpb $0x04, %ah                      /* fn 0x04, extended intialize */
  jnz chain_isr14h
int14h_init_port:
  /* check for init port = current port */
  pushw %ds
  pushw $BDA_SEG
  popw %ds                             /* ds = 0x40 */
  movw %dx, %bx                        /* bx = port number */
  shlw $1, %bx                         /* bx = port number * 2 */
  andw $7, %bx                         /* bx = bda offset of serial io addr */
  movw (%bx), %cx                      /* cx = io address of port to init */
  popw %ds                             /* restore original ds */
  cmpw %cx, %cs:serial_port_base_address
  jnz chain_isr14h                     /* if different, don't get in the way */
  /* init port == current port */
  pushw %ds
  /* LILO 22.6 HACK STARTS HERE */
  movw (%bp), %bx                      /* return address for int 14h call */
  movw 2(%bp), %ds                     /* return segment for int 14h call */
  cmpl $0x4f4c494c, 0x06               /* does segment have lilo signature? */
  jnz int14h_init_tail                 /* not lilo, bail on hack */
  cmpw $0x0616, 0x0a                   /* does version match lilo 22.6? */
  jnz int14h_init_tail                 /* unknown lilo release, bail on hack */
  movb $0, 0x12                        /* set lilo com port = 0 */
  movl $0x90c3585a, (%bx)              /* return code= pop dx;pop ax;ret;nop */
  /* now lilo 22.6's own serial out is permanently disabled */
  /* this prevents double-character output from int10h + serial */
  /* this also prevents lilo from stealing serial input chars */
  /* END LILO 22.6 HACK */
int14h_init_tail:
  popw %ds
  popaw
  pushw %dx                            /* get_serial_lsr trashes %dx */
  call get_serial_lsr                  /* return serial status in %al */
  xorb %ah, %ah                        /* return serial status in %ax */
  popw %dx                             /* restore %dx */
  iret
chain_isr14h:
  popaw
  jmp do_old_int14h

/*
 * int16h_isr
 *
 * entry point for int 16h
 *
 * keyboard characters are usually retrieved by calling
 * int 16h, generally placed in the keyboard buffer by
 * irq 1 (int 9h).  Poll serial port for new data before
 * chaining to int 16h to fake irq 1 behavior
 *
 * all registers preserved except flags (later iret will restore)
 * bda updated with a new keypress if available
 *
 * FIXME: handle multi-byte keypresses like cursor up/down
 * to send proper scancodes for navigating lilo menus
 */

int16h_isr:
  pushw %ax
  pushw %dx
  /* each time int 16h is invoked, fake an int 9h */
  /* except read the serial input buffer */
  /* then chain to the original int 16h for processing */
  call get_serial_lsr
  jz chain_isr16h                      /* no port present... */
  testb $1, %al                        /* bit 0 of LSR = 1 = data available */
  jz chain_isr16h                      /* no input waiting */
  call serial_get_input                /* get input and stuff kbd buffer */
  /* for now, leave remaining chars pending in serial fifo */
  /* int 16h callers only get one char at a time anyway */
chain_isr16h:
  popw %dx
  popw %ax
  jmp do_old_int16h

/*
 * update serial_cursor
 *
 * figure out where the cursor was, and where it's going
 * use the minimal amount of serial output to get it there
 * input: vga cursor and serial cursor positions stored in BDA
 *
 * all registers preserved except flags
 * bda updated with new position for serial console cursor
 */
update_serial_cursor:
  pushw %ax
  pushw %bx
  pushw %dx
  pushw %ds
  pushw $BDA_SEG
  popw %ds                             /* ds = 0x40 */
  call get_current_cursor              /* dh = row, dl = col */
  movw BDA_SERIAL_POS, %bx             /* bh = row, bl = col */
  subb %dl, %bl                        /* -col update */
  negb %bl                             /* col update */
  subb %dh, %bh                        /* -row update */
  negb %bh                             /* row update */
  /* handle a few special movement cases */
  /* cr, lf, bs, bs+bs, space, else send full ansi position */
  orb %dl, %dl                         /* column zero? */
  jnz update_serial_cursor_lf
  movb $0x0d, %al                      /* CR */
  call send_byte
  xorb %bl, %bl                        /* mark no diff in col */
update_serial_cursor_lf:
  cmpb $1, %bh                         /* +1 row? */
  jnz update_serial_cursor_bs
  movb $0x0a, %al                      /* LF */
  call send_byte
  xorb %bh, %bh                        /* mark no diff in row */
update_serial_cursor_bs:
  cmpb $-1, %bl                        /* one char back */
  jz update_serial_cursor_one_bs
  cmpb $-2, %bl                        /* two chars back */
  jnz update_serial_cursor_space       /* check for space */
  movb $0x08, %al                      /* BS */
  call send_byte
update_serial_cursor_one_bs:
  movb $0x08, %al                      /* BS */
  call send_byte
  xorb %bl, %bl                        /* mark no diff in col */
update_serial_cursor_space:
  cmpb $1, %bl                         /* one char forward */
  jnz update_serial_cursor_up
  movb $0x20, %al                      /* space */
  call send_byte
  xorb %bl, %bl                        /* mark no diff in col */
update_serial_cursor_up:
  cmpb $-1, %bh                        /* -1 row? */
  jnz update_serial_cursor_full        /* do full ansi pos update */
  call send_ansi_csi                   /* send ESC [ A (cursor up) */
  movb $0x41, %al                      /* A */
  call send_byte
  xorb %bh, %bh                        /* mark no diff in row */
update_serial_cursor_full:
  orw %bx, %bx                         /* diff = 0? */
  jz update_serial_cursor_done
  call send_ansi_cursor_pos            /* set cursor pos from dh,dl */
update_serial_cursor_done:
  movw %dx, BDA_SERIAL_POS
  popw %ds
  popw %dx
  popw %bx
  popw %ax
  ret

/*
 * write_teletype
 *
 * handle int 10h, function 0eh
 *
 * ah = 0x0e write teletype character
 * al = character ascii code
 * bh = display page number
 *
 * all registers except %al preserved
 * caller will restore all registers
 */

write_teletype:
  pushw %bx
  movb $0x07, %bl                      /* black bg, white fg */
  call send_attribute
  popw %bx
  call send_char_tty
  ret

/*
 * write_attr_char
 *
 * handle int 10h, function 09h
 *
 * ah = 0x09 write attribute/character at current cursor position
 * al = character ascii code
 * bh = display page number
 * bl = character attribute
 * cx = repetition count
 *
 * does not update cursor position
 * all registers except %cx and %al preserved
 * caller will restore all registers
 */

write_attr_char:
  call send_attribute                  /* send attribute in %bl */
  jmp write_char_common

/*
 * write_char
 *
 * handle int 10h, function 0ah
 *
 * ah = 0x0a write character at current cursor position
 * al = character ascii code
 * bh = display page number
 * cx = repetition count
 *
 * does not update cursor position
 * all registers except %cx and %al preserved
 * caller will restore all registers
 */

write_char:
  pushw %bx
  movb $0x07, %bl                      /* black bg, white fg */
  call send_attribute
  popw %bx
write_char_common:
  call get_current_cursor
  call send_char
  /* make cx=0 and cx=1 only output one char */
  cmpw $1, %cx
  jbe write_char_tail
  decw %cx
  jmp write_char
write_char_tail:
  /* put cursor back where it was on entry */
  call set_current_cursor
  ret

/*
 * write_string
 *
 * handle int 10h, function 13h
 *
 * ah = 0x13 write character at current cursor position
 * al = 0, data = char, ..., no cursor update
 * al = 1, data = char, ..., cursor at end of string
 * al = 2, data = char+attr, ..., no cursor update
 * al = 3, data = char+attr, ..., cursor at end of string
 * bh = display page number
 * bl = character attribute for all chars (if al = 0 or 1)
 * cx = characters in string (attributes don't count)
 * dh = cursor row start
 * dl = cursor column start
 * es:bp = pointer to source text string in memory
 *
 * all registers preserved except flags
 * caller will restore all registers
 */
write_string:
  call set_cursor_position
  pushw %ds
  pushw %es
  pushw %es
  popw %ds                             /* ds = es */
  movw %bp, %si                        /* si = bp */
  testb $2, %al
  jnz write_attr_string
  call send_attribute                  /* send attribute in %bl */
  test %cx, %cx
  jz write_string_empty
  call send_string                     /* plaintext out */
write_string_empty:
  jmp write_string_update_cursor
write_attr_string:
  call send_attr_string                /* text+attrib out */
write_string_update_cursor:
  testb $1, %al                        /* cursor update? */
  jnz write_string_tail                /* yes?  already happened */
  /* restore entry cursor position if no update */
  call set_cursor_position
write_string_tail:
  popw %es
  popw %ds
  ret

/*
 * set_cursor_position
 *
 * handle int 10h, function 02h
 *
 * ah = 0x02 set cursor position
 * bh = display page number
 * dh = cursor row
 * dl = cursor column
 *
 * update bda cursor position with value in %dx
 * serial console cursor only updated on text output
 * this routine also called by set_current_cursor
 * which won't bother setting ah = 2
 *
 * all registers preserved except flags
 */

set_cursor_position:
  pushw %ax
  pushw %ds
  pushw $BDA_SEG
  popw %ds                             /* ds = 0x40 */
  movzbw %bh, %ax                      /* ax = page number */
  andb $0x07, %al                      /* prevent invalid page number */
  shlb $1, %al                         /* calculate word offset */
  addb $BDA_CURSOR_BUF, %al            /* ax = cursor save offset */
  movw %ax, %bx                        /* bx = cursor save offset */
  movw %dx, (%bx)                      /* save new cursor value */
  popw %ds
  popw %ax
  ret

/*
 * set_current_cursor
 *
 * get current display page number and call set_cursor_positon
 * to store the row/column value in dx to the bda
 *
 * all registers preserved except flags
 */

set_current_cursor:
  pushw %ds
  pushw %bx
  pushw $BDA_SEG
  popw %ds                             /* ds = 0x40 */
  movb BDA_ACTIVE_PAGE, %bh
  call set_cursor_position
  popw %bx
  popw %ds
  ret

/*
 * get_cursor_common
 *
 * read cursor position for page %bh from bda into %dx
 *
 * returns:
 * dh = cursor row
 * dl = cursor column
 * ch = cursor start scanline
 * cl = cursor end scanline
 *
 * all registers except %dx, %cx preserved
 */
get_cursor_common:
  pushw %bx
  pushw %ds
  pushw $BDA_SEG
  popw %ds                             /* ds = 0x40 */
  movzbw %bh, %bx                      /* dx = current page */
  andb $7, %bl
  shlb $1, %bl
  addb $BDA_CURSOR_BUF, %bl
  movw (%bx), %dx                      /* get cursor pos */
  movw BDA_CURSOR_SCAN, %cx
  popw %ds
  popw %bx
  ret

/*
 * get_current_cursor
 *
 * read cursor position for current page from bda into %dx
 *
 * returns:
 * dh = cursor row
 * dl = cursor column
 *
 * all registers except %dx preserved
 */

get_current_cursor:
  pushw %ds
  pushw %bx
  pushw %cx
  pushw $BDA_SEG
  popw %ds                             /* ds = 0x40 */
  movb BDA_ACTIVE_PAGE, %bh
  call get_cursor_common
  popw %cx
  popw %bx
  popw %ds
  ret

/*
 * get_cursor_position
 *
 * handle int 10h, function 03h
 *
 * ah = 0x02 get cursor position
 * bh = display page number
 *
 * returns:
 * ax = 0
 * ch = cursor start scanline
 * ch = cursor end scanline
 * dh = cursor row
 * dl = cursor column
 *
 * all registers except %ax, %cx, %dx preserved
 */

get_cursor_position:
  call bail_if_vga_attached            /* does not return if vga attached */
  popw %ax             /* not chaining, pop fake return address */
  popw %dx             /* not chaining, pop saved cursor position */
  popaw                /* not chaining to old int 10h, pop saved state */
  call get_cursor_common
  xorw %ax, %ax
  iret

/*
 * return_current_video_state
 *
 * handle int 10h, function 0fh
 *
 * ah = 0x0f return current video state
 *
 * returns:
 * ah = number of columns on screen (from 40:4a)
 * al = current video mode setting (from 40:49)
 * bh = active display page number (from 40:62)
 *
 * all registers except %ax and %bh preserved
 */

read_current_video_state:
  call bail_if_vga_attached            /* does not return if vga attached */
  popw %ax             /* not chaining, pop fake return address */
  popw %dx             /* not chaining, pop saved cursor position */
  popaw                /* not chaining to old int 10h, pop saved state */
  pushw %ds
  pushw $BDA_SEG
  popw %ds                             /* ds = 0x40 */
  movb BDA_COLS, %ah
  movb BDA_MODE_NUM, %al
  movb BDA_ACTIVE_PAGE, %bh
  popw %ds
  iret

/*
 * read_attr_char
 *
 * handle int 10h, function 08h
 *
 * ah = 0x08 read character/attribute from screen
 *
 * returns:
 * ah = attribute at current cursor position
 * al = character read from current cursor position
 *
 * all registers preserved except %ax and flags
 */

read_attr_char:
  call bail_if_vga_attached            /* does not return if vga attached */
  popw %ax             /* not chaining, pop fake return address */
  popw %dx             /* not chaining, pop saved cursor position */
  popaw                /* not chaining to old int 10h, pop saved state */
  pushw %ds
  pushw $BDA_SEG
  popw %ds                             /* ds = 0x40 */
  movb BDA_COLOR_VAL, %ah              /* return last color value */
  call sgabioslog_get_char
  popw %ds
  iret

/*
 * set_video_mode
 *
 * handle int 10h, function 00h
 *
 * ah = 0x00 set video mode
 * al = video mode
 *
 * unless bit 7 of al = 1, setting mode clears screen
 *
 * all registers preserved except %bh, %dx, flags
 */

set_video_mode:
  testb $0x80, %al                     /* preserve screen flag? */
  jnz set_video_mode_tail
  call send_ansi_csi
  movb $0x32, %al                      /* 2 */
  call send_byte
  movb $0x4a, %al                      /* J */
  call send_byte
set_video_mode_tail:
  movb $0x07, %bl                      /* white on black text */
  call send_attribute                  /* send attribute in %bl */
  /* set cursor position to 0,0 */
  xorb %bh, %bh                        /* page 0 */
  xorw %dx, %dx
  jmp set_cursor_position

/*
 * scroll_page_up
 *
 * handle int 10h, function 06h
 *
 * ah = 0x06 scroll current page up
 * al = scroll distance in character rows (0 blanks entire area)
 * bh = attribute to used on blanked lines
 * ch = top row (upper left corner) of window
 * cl = left-most column (upper left corner) of window
 * dh = bottom row (lower right corner) of window
 * dl = right-most column (lower right corner) of window
 *
 * all registers preserved except flags
 */

scroll_page_up:
  pushw %si
  pushw %dx
  call get_current_cursor              /* save current cursor */
  movw %dx, %si                        /* si = vga cursor pos */
  popw %dx
  cmpb $0, %al                         /* al = 0 = clear window */
  jz scroll_common_clear
  pushw %ax
  call send_ansi_csi                   /* CSI [ %al S */
  call send_number
  movb $0x53, %al                      /* S */
  call send_byte
  popw %dx
  popw %si
  ret

/*
 * scroll_common_clear
 *
 * common tail for up/down scrolls to clear window specified
 * in %cx and %dx.
 *
 * stack should contain saved copy of si
 * si = original vga cursor position on service entry
 * 
 * bh = attribute to used on blanked lines
 * ch = top row (upper left corner) of window
 * cl = left-most column (upper left corner) of window
 * dh = bottom row (lower right corner) of window
 * dl = right-most column (lower right corner) of window
 */
scroll_common_clear:
  pushw %ax
  xchgb %bl, %bh                       /* bl = attribute, bh = old bl */
  call send_attribute                  /* send attribute in %bl */
  xchgb %bl, %bh                       /* restore bx */
  pushw %ds
  pushw $BDA_SEG
  popw %ds                             /* ds = 0x40 */
  /* check to see if region is full screen, and attribute default */
  orw %cx, %cx                         /* is top left 0,0? */
  jnz scroll_common_window             /* no, handle window */
  cmpb $0x07, %bh                      /* is attribute white on black? */
  jnz scroll_common_window             /* no, must write spaces */
#ifdef LILO_CLEAR_WORKAROUND_NOT_REQUIRED
  cmpb %cs:term_cols, %dl              /* is right less than cols ? */
  jc scroll_common_window              /* if so, handle window */
  cmpb %cs:term_rows, %dh              /* is bottom less than rows ? */
  jc scroll_common_window              /* if so, handle window */
#endif
  /* safe to send standard clear screen sequence */
  call send_ansi_csi                   /* send ESC [ */
  movb $0x32, %al                      /* 2 */
  call send_byte
  movb $0x4a, %al                      /* J */
  call send_byte
  jmp scroll_common_tail
scroll_common_window:
  pushw %dx
  movw %cx, %dx                        /* dx = upper right */
  call set_current_cursor
  popw %dx
  pushw %cx
  /* setup cx with count of chars to clear per row */
  xorb %ch, %ch
  negb %cl
  addb %dl, %cl                        /* cl = dl - cl */
  incb %cl                             /* start = end col = clear 1 col */
  cmpb %cs:term_cols, %cl              /* is count < cols? */
  jc scroll_common_row_ok              /* if so then skip limit */
  movb %cs:term_cols, %cl              /* limit count to cols */
scroll_common_row_ok:
  jz scroll_common_row_done            /* count == 0 ? */
  movb $0x20, %al                      /* space */
scroll_common_space_loop:
  call send_char
  loop scroll_common_space_loop        /* send cx spaces */
scroll_common_row_done:
  popw %cx
  incb %ch                             /* top left now next row */
  cmpb %dh, %ch
  jbe scroll_common_window             /* do next row */
scroll_common_tail:
  popw %ds
  popw %ax
  pushw %dx
  movw %si, %dx                        /* dx = saved vga cursor pos */
  call set_current_cursor              /* restore saved cursor */
  popw %dx
  popw %si
  ret

/*
 * scroll_page_down
 *
 * handle int 10h, function 07h
 *
 * ah = 0x07 scroll current page down
 * al = scroll distance in character rows (0 blanks entire area)
 * bh = attribute to used on blanked lines
 * ch = top row (upper left corner) of window
 * cl = left-most column (upper left corner) of window
 * dh = bottom row (lower right corner) of window
 * dl = right-most column (lower right corner) of window
 *
 * FIXME: this routine doesn't handle windowing, it currently
 * only handles one line screen scrolls and erasing entire screen
 *
 * all registers preserved except flags
 */

scroll_page_down:
  pushw %si
  pushw %dx
  call get_current_cursor              /* save current cursor */
  movw %dx, %si                        /* si = vga cursor pos */
  popw %dx
  cmpb $0, %al                         /* al = 0 = clear window */
  jz scroll_common_clear
  pushw %ax
  call send_ansi_csi                   /* CSI [ %al T */
  call send_number
  movb $0x54, %al                      /* T */
  call send_byte
  popw %dx
  popw %si
  ret

/*
 * bail_if_vga_attached
 *
 * Check for vga installed, if not, return to caller.
 * If so, pop return address, return to chain_isr_10h
 *
 * expected that routine calling this one has chain_isr_10h
 * as the next item on the stack
 *
 * all registers except flags and sp preserved
 */

bail_if_vga_attached:
  cmpw $0xc000, %cs:old_int10h_seg     /* vga attached? */
  jnz bail_tail                        /* if not, don't modify stack */
  addw $2, %sp                         /* else drop first return address */
bail_tail:
  ret                                  /* return to caller or chain_isr_10h */

/*
 * int10h_isr
 *
 * entry point for int 10h
 *
 * save all registers, force return to chain to previous int10h isr
 * decide which function in ah needs to be dispatched
 *
 * ah = 0x00 set mode
 * ah = 0x01 set cursor type
 * ah = 0x02 set cursor position
 * ah = 0x03 read cursor position
 * ah = 0x04 read light pen position
 * ah = 0x05 set active display page
 * ah = 0x06 scroll active page up
 * ah = 0x07 scroll active page down
 * ah = 0x08 read attribute/character at cursor
 * ah = 0x09 write attribute/character at cursor
 * ah = 0x0a write character at cursor position
 * ah = 0x0b set color palette
 * ah = 0x0c write pixel
 * ah = 0x0d read pixel
 * ah = 0x0e write teletype
 * ah = 0x0f read current video state
 * ah = 0x10 set individual palette registers
 * ah = 0x11 character generation (font control/info)
 * ah = 0x12 alternate select (video control/info)
 * ah = 0x13 write string
 * ah = 0x1a read/write display combination code
 * ah = 0x1b return functionality/state information
 * ah = 0x1c save/restore video state
 * ah = 0x4f vesa bios calls
 * all registers preserved except flags (later iret will restore)
 */

int10h_isr:
  pushaw
  call get_current_cursor
  pushw %dx                            /* save current cursor */
  pushw %bp                            /* need bp for indexing off stack */
  movw %sp, %bp                        /* bp = sp */
  movw 14(%bp), %dx                    /* restore dx from earlier pushaw */
  popw %bp                             /* restore old bp */
  pushw $chain_isr10h                  /* force return to chain_isr10h */
  testb %ah, %ah
  jnz int10h_02
  jmp set_video_mode
int10h_02:
  cmpb $0x02, %ah
  jnz int10h_03
  jmp set_cursor_position
int10h_03:
  cmpb $0x03, %ah
  jnz int10h_06
  jmp get_cursor_position
int10h_06:
  cmpb $0x06, %ah
  jnz int10h_07
  jmp scroll_page_up
int10h_07:
  cmpb $0x07, %ah
  jnz int10h_08
  jmp scroll_page_down
int10h_08:
  cmpb $0x08, %ah
  jnz int10h_09
  jmp read_attr_char
int10h_09:
  cmpb $0x09, %ah
  jnz int10h_0a
  jmp write_attr_char
int10h_0a:
  cmpb $0x0a, %ah
  jnz int10h_0e
  jmp write_char
int10h_0e:
  cmpb $0x0e, %ah
  jnz int10h_0f
  jmp write_teletype
int10h_0f:
  cmpb $0x0f, %ah
  jnz int10h_13
  jmp read_current_video_state
int10h_13:
  cmpb $0x13, %ah
  jnz int10h_default
  jmp write_string
int10h_default:
  popw %ax                             /* pop chain_isr10h return address */
chain_isr10h:
  popw %dx                             /* pop saved cursor */
  cmpw $0xc000, %cs:old_int10h_seg     /* vga attached? */
  jnz chain_post_cursor                /* if not, don't restore the cursor */
  call set_current_cursor              /* restore cursor if vga attached */
chain_post_cursor:
  popaw
  jmp do_old_int10h

/*
 * pnp_sga_init
 *
 * handle PnP initialization of option rom
 *
 * es:di = pointer to PnP structure
 * ax = indication as to which vectors should be hooked
 *      by specifying th type of boot device this has
 *      been selected as
 *      bit 7..3= reserved(0)
 *      bit 2   = 1 = connect as IPL (int 13h)
 *      bit 1   = 1 = connect as primary video (int 10h)
 *      bit 0   = 1 = connect as primary input (int 9h)
 * bx = card select number (probably 0xffff)
 * dx = read data port address (probably 0xffff)
 *
 * return:
 * ax = initialization status
 * bit 8    = 1 = IPL device supports int 13h block dev format
 * bit 7    = 1 = Output device supports int 10h char output
 * bit 6    = 1 = Input device supports int 9h char input
 * bit 5..4 = 00 = no IPL device attached
 *            01 = unknown whether or not IPL device attached
 *            10 = IPL device attached (RPL devices have connection)
 *            11 = reserved
 * bit 3..2 = 00 = no display device attached
 *            01 = unknown whether or not display device attached
 *            10 = display device attached
 *            11 = reserved
 * bit 1..0 = 00 = no input device attached
 *            01 = unknown whether or not input device attached
 *            10 = input device attached
 *            11 = reserved
 *
 * all registers preserved except %ax
 */

pnp_sga_init:
  /* FIXME: this is *wrong* -- init only what bios says to init */
  movw $0xca, %ax      /* 0xca = attached int 10h, 9h display, input */

/*
 * sga_init
 *
 * legacy option rom entry point
 *
 * all registers preserved
 */

sga_init:
  /* this is probably paranoid about register preservation */
  pushfw
  cli                                  /* more paranoia */
  pushaw
  pushw %ds
  pushw %es
  pushw $0
  popw %es                             /* es = 0 */
  pushw %cs
  popw %ds                             /* ds = cs */
  /* get original ISR */
  movl %es:0x28, %eax                  /* eax = old irq 3/int 0bh */
  movl %eax, old_irq3                  /* save away old irq 4/int 0bh */
  movl %es:0x2c, %eax                  /* eax = old irq 4/int 0ch */
  movl %eax, old_irq4                  /* save away old irq 4/int 0ch */
  movl %es:0x40, %eax                  /* eax = old int 10h */
  movl %eax, old_int10h                /* save away old int 10h */
  movl %es:0x50, %eax                  /* eax = old int 14h */
  movl %eax, old_int14h                /* save away old int 14h */
  movl %es:0x58, %eax                  /* eax = old int 16h */
  movl %eax, old_int16h                /* save away old int 16h */
  movw $irq3_isr, %es:0x28             /* new irq 3 offset */
  movw %cs, %es:0x2a                   /* write new irq 3 seg */
  movw $irq4_isr, %es:0x2c             /* new irq 4 offset */
  movw %cs, %es:0x2e                   /* write new irq 4 seg */
  movw $int10h_isr, %es:0x40           /* new int 10h offset */
  movw %cs, %es:0x42                   /* write new int10h seg */
  movw $int14h_isr, %es:0x50           /* new int 14h offset */
  movw %cs, %es:0x52                   /* write new int14h seg */
  movw $int16h_isr, %es:0x58           /* new int 16h offset */
  movw %cs, %es:0x5a                   /* write new int16h seg */
  /* empty input buffer to prepare for terminal sizing */
  call init_serial_port
input_clear_loop:
  call get_byte
  jnz input_clear_loop
  movw $term_init_string, %si
  call send_asciz_out
  push $BDA_SEG
  push $BDA_SEG
  popw %ds                             /* ds = 0x40 */
  popw %es                             /* es = 0x40 */
  movw $BDA_CURSOR_BUF, %di
input_timeout_loop:
  /* get input from terminal until timeout found */
  /* store input at 40:50 - 40:5e (cursor pos) */
  call poll_byte
  jz input_timeout
  stosb                                /* es:di */
  cmpw $0x5f, %di                      /* 14 characters max */
  jnz input_timeout_loop               /* good for more data */
input_timeout:
  xorb %al, %al                        /* nul terminate input */
  stosb
  cmpw $0x58, %di                      /* less than 8 chars? */
  jc resize_end                        /* too small to have valid data */
  movw $BDA_CURSOR_BUF, %si            /* point to start */
  lodsw                                /* ax = first 2 chars */
  cmpw $0x5b1b, %ax                    /* was it "ESC[" ? */
  jnz resize_end                       /* reply starts ESC[row;colR */
  xorb %bl, %bl                        /* bl = ascii->int conversion */
input_first_number:
  lodsb                                /* al = next char */
  cmpb $0x30, %al
  jc resize_end                        /* char < 0x30 invalid */
  cmpb $0x3a, %al                      /* is char < 0x3a */
  jnc input_semicolon
  andb $0x0f, %al                      /* al = 0 - 9 */
  movb %bl, %ah                        /* ah = last conversion */
  aad                                  /* ax = (al + ah * 10) & 0xff */
  movb %al, %bl                        /* bl = row ascii->int conversion */
  jmp input_first_number
input_semicolon:
  /* at this point bl should contain rows, al = ; */
  /* sanity check, bail if invalid */
  cmpb $0x3b, %al
  jnz resize_end                       /* invalid input found */
  cmpb $0x0a, %bl                      /* less than 10 rows? */
  jc suspect_loopback                  /* consider input invalid */
  xorb %bh, %bh                        /* bh = col ascii->int conversion */
input_second_number:
  lodsb                                /* al = next char */
  cmpb $0x30, %al
  jc resize_end                        /* char < 0x30 invalid */
  cmpb $0x3a, %al                      /* is char < 0x3a */
  jnc input_final_r
  andb $0x0f, %al                      /* al = 0 - 9 */
  movb %bh, %ah                        /* ah = last conversion */
  aad                                  /* ax = (al + ah * 10) & 0xff */
  movb %al, %bh                        /* bh = ascii->int conversion */
  jmp input_second_number
input_final_r:
  cmpb $0x52, %al                      /* is al = 'R' ? */
  jnz suspect_loopback                 /* invalid input found */
  movb %bl, %cs:term_rows              /* save away bl rows value */
  cmpw $0xc000, %cs:old_int10h_seg     /* vga attached? */
  jz resize_end                        /* if so, leave term_cols at 80 */
  movb %bh, %cs:term_cols              /* save away bh cols value */
  jmp resize_end
suspect_loopback:
  /*
   * characters were received that look like what we sent out
   * at this point, assume that a loopback device was plugged in
   * and disable any future serial port reads or writes, by pointing
   * output to port 0x2e8 (COM4) instead of 0x3f8 -- it's expected
   * that this is safe since a real port responds correctly and a
   * missing port will respond with 0xff which will terminate the
   * loop that waits for the "right" status on the port.
   */
  movw $0x2e8, %cs:serial_port_base_address
resize_end:
  /* clear (hopefully) overwritten cursor position buffer */
  xorb %al, %al
  movw $BDA_CURSOR_BUF, %di
  movw $0x10, %cx
  cld
  rep
  stosb                                /* fill 40:50 - 40:5f with 0 */
  pushw %cs
  popw %ds                             /* ds = cs */
  call get_byte                        /* flush any remaining "wrong" input */
  jnz resize_end
  call send_crlf                       /* place cursor on start of last line */
  movw $mfg_string, %si
  call send_asciz_out
  call send_crlf
  movw $prod_string, %si
  call send_asciz_out
  call send_crlf
  movw $long_version, %si
  call send_asciz_out
  call send_crlf
  /* if vga attached, skip terminal message and bda setup... */
  cmpw $0xc000, %cs:old_int10h_seg     /* vga attached? */
  jz post_bda_init_tail                /* if so, don't modify BDA */
  /* show detected terminal size, or default if none detected */
  movw $term_info, %si
  call send_asciz_out
  pushw $BDA_SEG
  popw %ds                             /* ds = 0x40 */
  movb %cs:term_cols, %al
  movb %al, BDA_COLS                   /* 40:4a = number of character cols */
  movb $0, BDA_CURSOR_COL              /* 40:51 = cursor0 col */
  call send_number
  movb $0x78, %al                      /* x */
  call send_byte
  movb %cs:term_rows, %al
  movb %al, %ah
  decb %ah                             /* ah = rows-1 */
  movb %ah, BDA_ROWS                   /* 40:84 = num character rows - 1 */
  movb %ah, BDA_CURSOR_ROW             /* 40:50 = cursor0 row */
  call send_number
  call send_crlf
  movb $3, BDA_MODE_NUM
  movb $0x29, BDA_MODE_SEL
  movw $VGA_IO_BASE, BDA_6845_ADDR
  movw $0x4000, BDA_PAGE_SIZE          /* 16KB per video page */
  /* to avoid ansi colors every character, store last attribute */
  movb $0x07, BDA_COLOR_VAL            /* 07 = black bg, white fg */
  movw %cs, %ax
  movw $_start, BDA_ROM_OFF
  movw %ax, BDA_ROM_SEG
post_bda_init_tail:
  /* copy BDA rows/cols to sgabios location... */
  /* if vga card is installed, reuse those values... */
  /* if no vga card is installed, this shouldn't change anything */
  pushw $BDA_SEG
  popw %ds                             /* ds = 0x40 */
  movb BDA_ROWS, %al
  incb %al                             /* bda holds rows-1 */
  movb %al, %cs:term_rows              /* sgabios rows */
  movb BDA_COLS, %ah
  movb %ah, %cs:term_cols              /* sgabios cols */
  /* setup in-memory logging of console if desired... */
  call setup_memconsole
  /* setup logging of last 256 characters output, if ebda has room */
  call sgabioslog_setup_ebda
  movw $ebda_info, %si
  call send_asciz_out
  movw %cs:sgabios_ebda_logbuf_offset, %ax
  xchgb %ah, %al
  call send_number
  movb $0x20, %al
  call send_byte
  movb %ah, %al
  call send_number
  call send_crlf
  popw %es
  popw %ds
  popaw
  popf
  lret

_end_sgabios:
