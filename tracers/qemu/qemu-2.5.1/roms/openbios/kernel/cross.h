/* memory access abstraction layer for forth kernel
 *
 * Copyright (C) 2005 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#ifndef __CROSS_H
#define __CROSS_H 1

/* The forthstrap compiler has to abstract the underlying dictionary
 * type: big/little endian, 32/64bit. All other binaries shall use
 * unchanged memory access for performance.
 */

/* byte swapping */

#ifndef SWAP_ENDIANNESS

/* trivial case - we don't have to change anything */
#define read_ucell(addr) (*(ucell *)(addr))
#define read_cell(addr)  (*(cell *)(addr))
#define read_long(addr)  (*(u32 *)(addr))
#define read_word(addr)  (*(u16 *)(addr))
#define read_byte(addr)  (*(u8 *)(addr))

#define write_ucell(addr, value) {*(ucell *)(addr)=(value);}
#define write_cell(addr, value)  {*(cell *)(addr)=(value);}
#define write_long(addr, value)  {*(u32 *)(addr)=(value);}
#define write_word(addr, value)  {*(u16 *)(addr)=(value);}
#define write_byte(addr, value)  {*(u8 *)(addr)=(value);}

#define target_ucell(x) (x)
#define target_cell(x) (x)
#define target_long(x) (x)
#define target_ulong(x) (x)

#else /* SWAP_ENDIANNESS */

#define target_word(value) ( (((value)>>8)&0xff) | (((value)&0xff)<<8) )
#define target_long(value) ( (((value)&0xff000000)>>24)|(((value)&0x00ff0000)>>8)|(((value)&0xff00)<<8)|(((value)&0xff)<<24) )
#define target_ulong(value) (target_long(value))

#if BITS==32
#define target_ucell(value) ((ucell)target_long(value))
#define target_cell(value) ((cell)target_long(value))
#elif BITS==64
#define target_ucell(value)                                             \
    ((((ucell)target_long((value) & 0xffffffff)) << 32) |               \
     ((ucell)target_long((value) >> 32)))
#define target_cell(value)                                              \
    ((((cell)target_long((value) & 0xffffffff)) << 32) |                \
     ((cell)target_long((value) >> 32)))
#else
#error "Endianness not supported. Please report."
#endif

#define read_ucell(addr) target_ucell(*(ucell *)(addr))
#define read_cell(addr)  target_cell(*(cell *)(addr))
#define read_long(addr)  target_long(*(u32 *)(addr))
#define read_word(addr)  target_word(*(u16 *)(addr))
#define read_byte(addr)  (*(u8 *)(addr))

#define write_ucell(addr, value) {*(ucell *)(addr)=target_ucell(value);}
#define write_cell(addr, value)  {*(cell *)(addr)=target_cell(value);}
#define write_long(addr, value)  {*(u32 *)(addr)=target_long(value);}
#define write_word(addr, value)  {*(u16 *)(addr)=target_word(value);}
#define write_byte(addr, value)  {*(u8 *)(addr)=(value);}
#endif

#ifdef CONFIG_LITTLE_ENDIAN
#define unaligned_read_word(addr) \
	    (read_byte(addr)|(read_byte((u8 *)addr+1)<<8))

#define unaligned_read_long(addr) \
	    (unaligned_read_word(addr)|(unaligned_read_word((u8 *)addr+2)<<16))

#define unaligned_write_word(addr, value) \
	write_byte(addr, (value & 0xff)); write_byte((u8 *)(addr+1), (value>>8))

#define unaligned_write_long(addr, value) \
	unaligned_write_word(addr, (value & 0xffff)); \
	unaligned_write_word((addr + 2), (value >> 16))

#endif

#ifdef CONFIG_BIG_ENDIAN
#define unaligned_read_word(addr) \
	    ((read_byte(addr)<<8)|read_byte((u8 *)addr+1))

#define unaligned_read_long(addr) \
	    ((unaligned_read_word(addr)<<16)|unaligned_read_word((u8 *)addr+2))

#define unaligned_write_word(addr, value) \
	write_byte(addr, (value >> 8)); write_byte((u8 *)(addr+1), (value & 0xff)) 

#define unaligned_write_long(addr, value) \
	unaligned_write_word(addr, (value >> 16)); \
	unaligned_write_word((addr + 2), (value & 0xffff))
#endif

/* bit width handling */

#if BITS==32
#define FMT_CELL_x PRIx32
#define FMT_CELL_d PRId32
#else
#define FMT_CELL_x PRIx64
#define FMT_CELL_d PRId64
#endif

#ifdef NATIVE_BITWIDTH_SMALLER_THAN_HOST_BITWIDTH
extern unsigned long base_address;
#define pointer2cell(x) ((ucell)(((unsigned long)(x))-base_address))
#define cell2pointer(x) ((u8 *)(((unsigned long)(x))+base_address))
#endif

#ifdef NATIVE_BITWIDTH_LARGER_THAN_HOST_BITWIDTH
#define pointer2cell(x) ((ucell)(unsigned long)(x))
#define cell2pointer(x) ((u8 *)((unsigned long)(x)&0xFFFFFFFFUL))
#endif

#endif
