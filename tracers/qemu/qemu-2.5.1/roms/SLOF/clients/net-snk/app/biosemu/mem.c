/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <cpu.h>
#include "debug.h"
#include "device.h"
#include "x86emu/x86emu.h"
#include "biosemu.h"
#include <time.h>
#include "mem.h"

// define a check for access to certain (virtual) memory regions (interrupt handlers, BIOS Data Area, ...)
#ifdef DEBUG
static uint8_t in_check = 0;	// to avoid recursion...
uint16_t ebda_segment;
uint32_t ebda_size;

//TODO: these macros have grown so large, that they should be changed to an inline function,
//just for the sake of readability...

//declare prototypes of the functions to follow, for use in DEBUG_CHECK_VMEM_ACCESS
uint8_t my_rdb(uint32_t);
uint16_t my_rdw(uint32_t);
uint32_t my_rdl(uint32_t);

#define DEBUG_CHECK_VMEM_READ(_addr, _rval) \
   if ((debug_flags & DEBUG_CHECK_VMEM_ACCESS) && (in_check == 0)) { \
         in_check = 1; \
         /* determine ebda_segment and size \
          * since we are using my_rdx calls, make sure, this is after setting in_check! */ \
         /* offset 03 in BDA is EBDA segment */ \
         ebda_segment = my_rdw(0x40e); \
         /* first value in ebda is size in KB */ \
         ebda_size = my_rdb(ebda_segment << 4) * 1024; \
			/* check Interrupt Vector Access (0000:0000h - 0000:0400h) */ \
			if (_addr < 0x400) { \
				DEBUG_PRINTF_CS_IP("%s: read from Interrupt Vector %x --> %x\n", \
						__FUNCTION__, _addr / 4, _rval); \
			} \
			/* access to BIOS Data Area (0000:0400h - 0000:0500h)*/ \
			else if ((_addr >= 0x400) && (addr < 0x500)) { \
				DEBUG_PRINTF_CS_IP("%s: read from BIOS Data Area: addr: %x --> %x\n", \
						__FUNCTION__, _addr, _rval); \
				/* dump registers */ \
				/* x86emu_dump_xregs(); */ \
			} \
			/* access to first 64k of memory... */ \
			else if (_addr < 0x10000) { \
				DEBUG_PRINTF_CS_IP("%s: read from segment 0000h: addr: %x --> %x\n", \
						__FUNCTION__, _addr, _rval); \
				/* dump registers */ \
				/* x86emu_dump_xregs(); */ \
			} \
			/* read from PMM_CONV_SEGMENT */ \
			else if ((_addr <= ((PMM_CONV_SEGMENT << 4) | 0xffff)) && (_addr >= (PMM_CONV_SEGMENT << 4))) { \
				DEBUG_PRINTF_CS_IP("%s: read from PMM Segment %04xh: addr: %x --> %x\n", \
						__FUNCTION__, PMM_CONV_SEGMENT, _addr, _rval); \
				/* HALT_SYS(); */ \
				/* dump registers */ \
				/* x86emu_dump_xregs(); */ \
			} \
			/* read from PNP_DATA_SEGMENT */ \
			else if ((_addr <= ((PNP_DATA_SEGMENT << 4) | 0xffff)) && (_addr >= (PNP_DATA_SEGMENT << 4))) { \
				DEBUG_PRINTF_CS_IP("%s: read from PnP Data Segment %04xh: addr: %x --> %x\n", \
						__FUNCTION__, PNP_DATA_SEGMENT, _addr, _rval); \
				/* HALT_SYS(); */ \
				/* dump registers */ \
				/* x86emu_dump_xregs(); */ \
			} \
			/* read from EBDA Segment */ \
			else if ((_addr <= ((ebda_segment << 4) | (ebda_size - 1))) && (_addr >= (ebda_segment << 4))) { \
				DEBUG_PRINTF_CS_IP("%s: read from Extended BIOS Data Area %04xh, size: %04x: addr: %x --> %x\n", \
						__FUNCTION__, ebda_segment, ebda_size, _addr, _rval); \
			} \
			/* read from BIOS_DATA_SEGMENT */ \
			else if ((_addr <= ((BIOS_DATA_SEGMENT << 4) | 0xffff)) && (_addr >= (BIOS_DATA_SEGMENT << 4))) { \
				DEBUG_PRINTF_CS_IP("%s: read from BIOS Data Segment %04xh: addr: %x --> %x\n", \
						__FUNCTION__, BIOS_DATA_SEGMENT, _addr, _rval); \
				/* for PMM debugging */ \
				/*if (_addr == BIOS_DATA_SEGMENT << 4) { \
					X86EMU_trace_on(); \
					M.x86.debug &= ~DEBUG_DECODE_NOPRINT_F; \
				}*/ \
				/* dump registers */ \
				/* x86emu_dump_xregs(); */ \
			} \
         in_check = 0; \
   }
#define DEBUG_CHECK_VMEM_WRITE(_addr, _val) \
   if ((debug_flags & DEBUG_CHECK_VMEM_ACCESS) && (in_check == 0)) { \
         in_check = 1; \
         /* determine ebda_segment and size \
          * since we are using my_rdx calls, make sure, this is after setting in_check! */ \
         /* offset 03 in BDA is EBDA segment */ \
         ebda_segment = my_rdw(0x40e); \
         /* first value in ebda is size in KB */ \
         ebda_size = my_rdb(ebda_segment << 4) * 1024; \
			/* check Interrupt Vector Access (0000:0000h - 0000:0400h) */ \
			if (_addr < 0x400) { \
				DEBUG_PRINTF_CS_IP("%s: write to Interrupt Vector %x <-- %x\n", \
						__FUNCTION__, _addr / 4, _val); \
			} \
			/* access to BIOS Data Area (0000:0400h - 0000:0500h)*/ \
			else if ((_addr >= 0x400) && (addr < 0x500)) { \
				DEBUG_PRINTF_CS_IP("%s: write to BIOS Data Area: addr: %x <-- %x\n", \
						__FUNCTION__, _addr, _val); \
				/* dump registers */ \
				/* x86emu_dump_xregs(); */ \
			} \
			/* access to first 64k of memory...*/ \
			else if (_addr < 0x10000) { \
				DEBUG_PRINTF_CS_IP("%s: write to segment 0000h: addr: %x <-- %x\n", \
						__FUNCTION__, _addr, _val); \
				/* dump registers */ \
				/* x86emu_dump_xregs(); */ \
			} \
			/* write to PMM_CONV_SEGMENT... */ \
			else if ((_addr <= ((PMM_CONV_SEGMENT << 4) | 0xffff)) && (_addr >= (PMM_CONV_SEGMENT << 4))) { \
				DEBUG_PRINTF_CS_IP("%s: write to PMM Segment %04xh: addr: %x <-- %x\n", \
						__FUNCTION__, PMM_CONV_SEGMENT, _addr, _val); \
				/* dump registers */ \
				/* x86emu_dump_xregs(); */ \
			} \
			/* write to PNP_DATA_SEGMENT... */ \
			else if ((_addr <= ((PNP_DATA_SEGMENT << 4) | 0xffff)) && (_addr >= (PNP_DATA_SEGMENT << 4))) { \
				DEBUG_PRINTF_CS_IP("%s: write to PnP Data Segment %04xh: addr: %x <-- %x\n", \
						__FUNCTION__, PNP_DATA_SEGMENT, _addr, _val); \
				/* dump registers */ \
				/* x86emu_dump_xregs(); */ \
			} \
			/* write to EBDA Segment... */ \
			else if ((_addr <= ((ebda_segment << 4) | (ebda_size - 1))) && (_addr >= (ebda_segment << 4))) { \
				DEBUG_PRINTF_CS_IP("%s: write to Extended BIOS Data Area %04xh, size: %04x: addr: %x <-- %x\n", \
						__FUNCTION__, ebda_segment, ebda_size, _addr, _val); \
			} \
			/* write to BIOS_DATA_SEGMENT... */ \
			else if ((_addr <= ((BIOS_DATA_SEGMENT << 4) | 0xffff)) && (_addr >= (BIOS_DATA_SEGMENT << 4))) { \
				DEBUG_PRINTF_CS_IP("%s: write to BIOS Data Segment %04xh: addr: %x <-- %x\n", \
						__FUNCTION__, BIOS_DATA_SEGMENT, _addr, _val); \
				/* dump registers */ \
				/* x86emu_dump_xregs(); */ \
			} \
			/* write to current CS segment... */ \
			else if ((_addr < ((M.x86.R_CS << 4) | 0xffff)) && (_addr > (M.x86.R_CS << 4))) { \
				DEBUG_PRINTF_CS_IP("%s: write to CS segment %04xh: addr: %x <-- %x\n", \
						__FUNCTION__, M.x86.R_CS, _addr, _val); \
				/* dump registers */ \
				/* x86emu_dump_xregs(); */ \
			} \
         in_check = 0; \
   }
#else
#define DEBUG_CHECK_VMEM_READ(_addr, _rval)
#define DEBUG_CHECK_VMEM_WRITE(_addr, _val)
#endif

//defined in net-snk/kernel/timer.c
extern uint64_t get_time(void);

void update_time(uint32_t);

// read byte from memory
uint8_t
my_rdb(uint32_t addr)
{
	uint64_t translated_addr = addr;
	uint8_t translated = dev_translate_address(&translated_addr);
	uint8_t rval;
	if (translated != 0) {
		//translation successful, access VGA Memory (BAR or Legacy...)
		DEBUG_PRINTF_MEM("%s(%08x): access to VGA Memory\n",
				 __FUNCTION__, addr);
		//DEBUG_PRINTF_MEM("%s(%08x): translated_addr: %llx\n", __FUNCTION__, addr, translated_addr);
		set_ci();
		rval = *((uint8_t *) translated_addr);
		clr_ci();
		DEBUG_PRINTF_MEM("%s(%08x) VGA --> %02x\n", __FUNCTION__, addr,
				 rval);
		return rval;
	} else if (addr > M.mem_size) {
		DEBUG_PRINTF("%s(%08x): Memory Access out of range!\n",
			     __FUNCTION__, addr);
		//disassemble_forward(M.x86.saved_cs, M.x86.saved_ip, 1);
		HALT_SYS();
	} else {
		/* read from virtual memory */
		rval = *((uint8_t *) (M.mem_base + addr));
		DEBUG_CHECK_VMEM_READ(addr, rval);
		return rval;
	}
	return -1;
}

//read word from memory
uint16_t
my_rdw(uint32_t addr)
{
	uint64_t translated_addr = addr;
	uint8_t translated = dev_translate_address(&translated_addr);
	uint16_t rval;
	if (translated != 0) {
		//translation successful, access VGA Memory (BAR or Legacy...)
		DEBUG_PRINTF_MEM("%s(%08x): access to VGA Memory\n",
				 __FUNCTION__, addr);
		//DEBUG_PRINTF_MEM("%s(%08x): translated_addr: %llx\n", __FUNCTION__, addr, translated_addr);
		// check for legacy memory, because of the remapping to BARs, the reads must
		// be byte reads...
		if ((addr >= 0xa0000) && (addr < 0xc0000)) {
			//read bytes a using my_rdb, because of the remapping to BARs
			//words may not be contiguous in memory, so we need to translate
			//every address...
			rval = ((uint8_t) my_rdb(addr)) |
			    (((uint8_t) my_rdb(addr + 1)) << 8);
		} else {
			if ((translated_addr & (uint64_t) 0x1) == 0) {
				// 16 bit aligned access...
				set_ci();
				rval = in16le((void *) translated_addr);
				clr_ci();
			} else {
				// unaligned access, read single bytes
				set_ci();
				rval = (*((uint8_t *) translated_addr)) |
				    (*((uint8_t *) translated_addr + 1) << 8);
				clr_ci();
			}
		}
		DEBUG_PRINTF_MEM("%s(%08x) VGA --> %04x\n", __FUNCTION__, addr,
				 rval);
		return rval;
	} else if (addr > M.mem_size) {
		DEBUG_PRINTF("%s(%08x): Memory Access out of range!\n",
			     __FUNCTION__, addr);
		//disassemble_forward(M.x86.saved_cs, M.x86.saved_ip, 1);
		HALT_SYS();
	} else {
		/* read from virtual memory */
		rval = in16le((void *) (M.mem_base + addr));
		DEBUG_CHECK_VMEM_READ(addr, rval);
		return rval;
	}
	return -1;
}

//read long from memory
uint32_t
my_rdl(uint32_t addr)
{
	uint64_t translated_addr = addr;
	uint8_t translated = dev_translate_address(&translated_addr);
	uint32_t rval;
	if (translated != 0) {
		//translation successful, access VGA Memory (BAR or Legacy...)
		DEBUG_PRINTF_MEM("%s(%x): access to VGA Memory\n",
				 __FUNCTION__, addr);
		//DEBUG_PRINTF_MEM("%s(%08x): translated_addr: %llx\n", __FUNCTION__, addr, translated_addr);
		// check for legacy memory, because of the remapping to BARs, the reads must
		// be byte reads...
		if ((addr >= 0xa0000) && (addr < 0xc0000)) {
			//read bytes a using my_rdb, because of the remapping to BARs
			//dwords may not be contiguous in memory, so we need to translate
			//every address...
			rval = ((uint8_t) my_rdb(addr)) |
			    (((uint8_t) my_rdb(addr + 1)) << 8) |
			    (((uint8_t) my_rdb(addr + 2)) << 16) |
			    (((uint8_t) my_rdb(addr + 3)) << 24);
		} else {
			if ((translated_addr & (uint64_t) 0x3) == 0) {
				// 32 bit aligned access...
				set_ci();
				rval = in32le((void *) translated_addr);
				clr_ci();
			} else {
				// unaligned access, read single bytes
				set_ci();
				rval = (*((uint8_t *) translated_addr)) |
				    (*((uint8_t *) translated_addr + 1) << 8) |
				    (*((uint8_t *) translated_addr + 2) << 16) |
				    (*((uint8_t *) translated_addr + 3) << 24);
				clr_ci();
			}
		}
		DEBUG_PRINTF_MEM("%s(%08x) VGA --> %08x\n", __FUNCTION__, addr,
				 rval);
		//HALT_SYS();
		return rval;
	} else if (addr > M.mem_size) {
		DEBUG_PRINTF("%s(%08x): Memory Access out of range!\n",
			     __FUNCTION__, addr);
		//disassemble_forward(M.x86.saved_cs, M.x86.saved_ip, 1);
		HALT_SYS();
	} else {
		/* read from virtual memory */
		rval = in32le((void *) (M.mem_base + addr));
		switch (addr) {
		case 0x46c:
			//BDA Time Data, update it, before reading
			update_time(rval);
			rval = in32le((void *) (M.mem_base + addr));
			break;
		}
		DEBUG_CHECK_VMEM_READ(addr, rval);
		return rval;
	}
	return -1;
}

//write byte to memory
void
my_wrb(uint32_t addr, uint8_t val)
{
	uint64_t translated_addr = addr;
	uint8_t translated = dev_translate_address(&translated_addr);
	if (translated != 0) {
		//translation successful, access VGA Memory (BAR or Legacy...)
		DEBUG_PRINTF_MEM("%s(%x, %x): access to VGA Memory\n",
				 __FUNCTION__, addr, val);
		//DEBUG_PRINTF_MEM("%s(%08x): translated_addr: %llx\n", __FUNCTION__, addr, translated_addr);
		set_ci();
		*((uint8_t *) translated_addr) = val;
		clr_ci();
	} else if (addr > M.mem_size) {
		DEBUG_PRINTF("%s(%08x): Memory Access out of range!\n",
			     __FUNCTION__, addr);
		//disassemble_forward(M.x86.saved_cs, M.x86.saved_ip, 1);
		HALT_SYS();
	} else {
		/* write to virtual memory */
		DEBUG_CHECK_VMEM_WRITE(addr, val);
		*((uint8_t *) (M.mem_base + addr)) = val;
	}
}

void
my_wrw(uint32_t addr, uint16_t val)
{
	uint64_t translated_addr = addr;
	uint8_t translated = dev_translate_address(&translated_addr);
	if (translated != 0) {
		//translation successful, access VGA Memory (BAR or Legacy...)
		DEBUG_PRINTF_MEM("%s(%x, %x): access to VGA Memory\n",
				 __FUNCTION__, addr, val);
		//DEBUG_PRINTF_MEM("%s(%08x): translated_addr: %llx\n", __FUNCTION__, addr, translated_addr);
		// check for legacy memory, because of the remapping to BARs, the reads must
		// be byte reads...
		if ((addr >= 0xa0000) && (addr < 0xc0000)) {
			//read bytes a using my_rdb, because of the remapping to BARs
			//words may not be contiguous in memory, so we need to translate
			//every address...
			my_wrb(addr, (uint8_t) (val & 0x00FF));
			my_wrb(addr + 1, (uint8_t) ((val & 0xFF00) >> 8));
		} else {
			if ((translated_addr & (uint64_t) 0x1) == 0) {
				// 16 bit aligned access...
				set_ci();
				out16le((void *) translated_addr, val);
				clr_ci();
			} else {
				// unaligned access, write single bytes
				set_ci();
				*((uint8_t *) translated_addr) =
				    (uint8_t) (val & 0x00FF);
				*((uint8_t *) translated_addr + 1) =
				    (uint8_t) ((val & 0xFF00) >> 8);
				clr_ci();
			}
		}
	} else if (addr > M.mem_size) {
		DEBUG_PRINTF("%s(%08x): Memory Access out of range!\n",
			     __FUNCTION__, addr);
		//disassemble_forward(M.x86.saved_cs, M.x86.saved_ip, 1);
		HALT_SYS();
	} else {
		/* write to virtual memory */
		DEBUG_CHECK_VMEM_WRITE(addr, val);
		out16le((void *) (M.mem_base + addr), val);
	}
}
void
my_wrl(uint32_t addr, uint32_t val)
{
	uint64_t translated_addr = addr;
	uint8_t translated = dev_translate_address(&translated_addr);
	if (translated != 0) {
		//translation successful, access VGA Memory (BAR or Legacy...)
		DEBUG_PRINTF_MEM("%s(%x, %x): access to VGA Memory\n",
				 __FUNCTION__, addr, val);
		//DEBUG_PRINTF_MEM("%s(%08x): translated_addr: %llx\n",  __FUNCTION__, addr, translated_addr);
		// check for legacy memory, because of the remapping to BARs, the reads must
		// be byte reads...
		if ((addr >= 0xa0000) && (addr < 0xc0000)) {
			//read bytes a using my_rdb, because of the remapping to BARs
			//words may not be contiguous in memory, so we need to translate
			//every address...
			my_wrb(addr, (uint8_t) (val & 0x000000FF));
			my_wrb(addr + 1, (uint8_t) ((val & 0x0000FF00) >> 8));
			my_wrb(addr + 2, (uint8_t) ((val & 0x00FF0000) >> 16));
			my_wrb(addr + 3, (uint8_t) ((val & 0xFF000000) >> 24));
		} else {
			if ((translated_addr & (uint64_t) 0x3) == 0) {
				// 32 bit aligned access...
				set_ci();
				out32le((void *) translated_addr, val);
				clr_ci();
			} else {
				// unaligned access, write single bytes
				set_ci();
				*((uint8_t *) translated_addr) =
				    (uint8_t) (val & 0x000000FF);
				*((uint8_t *) translated_addr + 1) =
				    (uint8_t) ((val & 0x0000FF00) >> 8);
				*((uint8_t *) translated_addr + 2) =
				    (uint8_t) ((val & 0x00FF0000) >> 16);
				*((uint8_t *) translated_addr + 3) =
				    (uint8_t) ((val & 0xFF000000) >> 24);
				clr_ci();
			}
		}
	} else if (addr > M.mem_size) {
		DEBUG_PRINTF("%s(%08x): Memory Access out of range!\n",
			     __FUNCTION__, addr);
		//disassemble_forward(M.x86.saved_cs, M.x86.saved_ip, 1);
		HALT_SYS();
	} else {
		/* write to virtual memory */
		DEBUG_CHECK_VMEM_WRITE(addr, val);
		out32le((void *) (M.mem_base + addr), val);
	}
}

//update time in BIOS Data Area
//DWord at offset 0x6c is the timer ticks since midnight, timer is running at 18Hz
//byte at 0x70 is timer overflow (set if midnight passed since last call to interrupt 1a function 00
//cur_val is the current value, of offset 6c...
void
update_time(uint32_t cur_val)
{
	//for convenience, we let the start of timebase be at midnight, we currently dont support
	//real daytime anyway...
	uint64_t ticks_per_day = tb_freq * 60 * 24;
	// at 18Hz a period is ~55ms, converted to ticks (tb_freq is ticks/second)
	uint32_t period_ticks = (55 * tb_freq) / 1000;
	uint64_t curr_time = get_time();
	uint64_t ticks_since_midnight = curr_time % ticks_per_day;
	uint32_t periods_since_midnight = ticks_since_midnight / period_ticks;
	// if periods since midnight is smaller than last value, set overflow
	// at BDA Offset 0x70
	if (periods_since_midnight < cur_val) {
		my_wrb(0x470, 1);
	}
	// store periods since midnight at BDA offset 0x6c
	my_wrl(0x46c, periods_since_midnight);
}
