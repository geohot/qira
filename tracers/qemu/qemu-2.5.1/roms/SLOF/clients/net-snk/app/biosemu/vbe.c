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
#include <stdlib.h>
#include <string.h>

#include <stdint.h>
#include <cpu.h>

#include "debug.h"

#include <x86emu/x86emu.h>
#include <x86emu/regs.h>
#include <x86emu/prim_ops.h>	// for push_word

#include "biosemu.h"
#include "io.h"
#include "mem.h"
#include "interrupt.h"
#include "device.h"
#include "vbe.h"

static X86EMU_memFuncs my_mem_funcs = {
	my_rdb, my_rdw, my_rdl,
	my_wrb, my_wrw, my_wrl
};

static X86EMU_pioFuncs my_pio_funcs = {
	my_inb, my_inw, my_inl,
	my_outb, my_outw, my_outl
};

// pointer to VBEInfoBuffer, set by vbe_prepare
uint8_t *vbe_info_buffer = 0;
// virtual BIOS Memory
uint8_t *biosmem;
uint32_t biosmem_size;

// these structs are for input from and output to OF
typedef struct {
	uint8_t display_type;	// 0=NONE, 1= analog, 2=digital
	uint16_t screen_width;
	uint16_t screen_height;
	uint16_t screen_linebytes;	// bytes per line in framebuffer, may be more than screen_width
	uint8_t color_depth;	// color depth in bpp
	uint32_t framebuffer_address;
	uint8_t edid_block_zero[128];
} __attribute__ ((__packed__)) screen_info_t;

typedef struct {
	uint8_t signature[4];
	uint16_t size_reserved;
	uint8_t monitor_number;
	uint16_t max_screen_width;
	uint8_t color_depth;
} __attribute__ ((__packed__)) screen_info_input_t;

// these structs only store a subset of the VBE defined fields
// only those needed.
typedef struct {
	char signature[4];
	uint16_t version;
	uint8_t *oem_string_ptr;
	uint32_t capabilities;
	uint16_t video_mode_list[256];	// lets hope we never have more than 256 video modes...
	uint16_t total_memory;
} vbe_info_t;

typedef struct {
	uint16_t video_mode;
	uint8_t mode_info_block[256];
	uint16_t attributes;
	uint16_t linebytes;
	uint16_t x_resolution;
	uint16_t y_resolution;
	uint8_t x_charsize;
	uint8_t y_charsize;
	uint8_t bits_per_pixel;
	uint8_t memory_model;
	uint32_t framebuffer_address;
} vbe_mode_info_t;

typedef struct {
	uint8_t port_number;	// i.e. monitor number
	uint8_t edid_transfer_time;
	uint8_t ddc_level;
	uint8_t edid_block_zero[128];
} vbe_ddc_info_t;

static inline uint8_t
vbe_prepare(void)
{
	vbe_info_buffer = biosmem + (VBE_SEGMENT << 4);	// segment:offset off VBE Data Area
	//clear buffer
	memset(vbe_info_buffer, 0, 512);
	//set VbeSignature to "VBE2" to indicate VBE 2.0+ request
	vbe_info_buffer[0] = 'V';
	vbe_info_buffer[0] = 'B';
	vbe_info_buffer[0] = 'E';
	vbe_info_buffer[0] = '2';
	// ES:DI store pointer to buffer in virtual mem see vbe_info_buffer above...
	M.x86.R_EDI = 0x0;
	M.x86.R_ES = VBE_SEGMENT;

	return 0;		// successful init
}

// VBE Function 00h
static uint8_t
vbe_info(vbe_info_t * info)
{
	vbe_prepare();
	// call VBE function 00h (Info Function)
	M.x86.R_EAX = 0x4f00;

	// enable trace
	CHECK_DBG(DEBUG_TRACE_X86EMU) {
		X86EMU_trace_on();
	}
	// run VESA Interrupt
	runInt10();

	if (M.x86.R_AL != 0x4f) {
		DEBUG_PRINTF_VBE("%s: VBE Info Function NOT supported! AL=%x\n",
				 __FUNCTION__, M.x86.R_AL);
		return -1;
	}

	if (M.x86.R_AH != 0x0) {
		DEBUG_PRINTF_VBE
		    ("%s: VBE Info Function Return Code NOT OK! AH=%x\n",
		     __FUNCTION__, M.x86.R_AH);
		return M.x86.R_AH;
	}
	//printf("VBE Info Dump:");
	//dump(vbe_info_buffer, 64);

	//offset 0: signature
	info->signature[0] = vbe_info_buffer[0];
	info->signature[1] = vbe_info_buffer[1];
	info->signature[2] = vbe_info_buffer[2];
	info->signature[3] = vbe_info_buffer[3];

	// offset 4: 16bit le containing VbeVersion
	info->version = in16le(vbe_info_buffer + 4);

	// offset 6: 32bit le containg segment:offset of OEM String in virtual Mem.
	info->oem_string_ptr =
	    biosmem + ((in16le(vbe_info_buffer + 8) << 4) +
		       in16le(vbe_info_buffer + 6));

	// offset 10: 32bit le capabilities
	info->capabilities = in32le(vbe_info_buffer + 10);

	// offset 14: 32 bit le containing segment:offset of supported video mode table
	uint16_t *video_mode_ptr;
	video_mode_ptr =
	    (uint16_t *) (biosmem +
			  ((in16le(vbe_info_buffer + 16) << 4) +
			   in16le(vbe_info_buffer + 14)));
	uint32_t i = 0;
	do {
		info->video_mode_list[i] = in16le(video_mode_ptr + i);
		i++;
	}
	while ((i <
		(sizeof(info->video_mode_list) /
		 sizeof(info->video_mode_list[0])))
	       && (info->video_mode_list[i - 1] != 0xFFFF));

	//offset 18: 16bit le total memory in 64KB blocks
	info->total_memory = in16le(vbe_info_buffer + 18);

	return 0;
}

// VBE Function 01h
static uint8_t
vbe_get_mode_info(vbe_mode_info_t * mode_info)
{
	vbe_prepare();
	// call VBE function 01h (Return VBE Mode Info Function)
	M.x86.R_EAX = 0x4f01;
	M.x86.R_CX = mode_info->video_mode;

	// enable trace
	CHECK_DBG(DEBUG_TRACE_X86EMU) {
		X86EMU_trace_on();
	}
	// run VESA Interrupt
	runInt10();

	if (M.x86.R_AL != 0x4f) {
		DEBUG_PRINTF_VBE
		    ("%s: VBE Return Mode Info Function NOT supported! AL=%x\n",
		     __FUNCTION__, M.x86.R_AL);
		return -1;
	}

	if (M.x86.R_AH != 0x0) {
		DEBUG_PRINTF_VBE
		    ("%s: VBE Return Mode Info (mode: %04x) Function Return Code NOT OK! AH=%02x\n",
		     __FUNCTION__, mode_info->video_mode, M.x86.R_AH);
		return M.x86.R_AH;
	}
	//pointer to mode_info_block is in ES:DI
	memcpy(mode_info->mode_info_block,
	       biosmem + ((M.x86.R_ES << 4) + M.x86.R_DI),
	       sizeof(mode_info->mode_info_block));

	//printf("Mode Info Dump:");
	//dump(mode_info_block, 64);

	// offset 0: 16bit le mode attributes
	mode_info->attributes = in16le(mode_info->mode_info_block);

	// offset 16: 16bit le bytes per scan line
	mode_info->linebytes = in16le(mode_info->mode_info_block + 16);

	// offset 18: 16bit le x resolution
	mode_info->x_resolution = in16le(mode_info->mode_info_block + 18);

	// offset 20: 16bit le y resolution
	mode_info->y_resolution = in16le(mode_info->mode_info_block + 20);

	// offset 22: 8bit le x charsize
	mode_info->x_charsize = *(mode_info->mode_info_block + 22);

	// offset 23: 8bit le y charsize
	mode_info->y_charsize = *(mode_info->mode_info_block + 23);

	// offset 25: 8bit le bits per pixel
	mode_info->bits_per_pixel = *(mode_info->mode_info_block + 25);

	// offset 27: 8bit le memory model
	mode_info->memory_model = *(mode_info->mode_info_block + 27);

	// offset 40: 32bit le containg offset of frame buffer memory ptr
	mode_info->framebuffer_address =
	    in32le(mode_info->mode_info_block + 40);

	return 0;
}

// VBE Function 02h
static uint8_t
vbe_set_mode(vbe_mode_info_t * mode_info)
{
	vbe_prepare();
	// call VBE function 02h (Set VBE Mode Function)
	M.x86.R_EAX = 0x4f02;
	M.x86.R_BX = mode_info->video_mode;
	M.x86.R_BX |= 0x4000;	// set bit 14 to request linear framebuffer mode
	M.x86.R_BX &= 0x7FFF;	// clear bit 15 to request clearing of framebuffer

	DEBUG_PRINTF_VBE("%s: setting mode: 0x%04x\n", __FUNCTION__,
			 M.x86.R_BX);

	// enable trace
	CHECK_DBG(DEBUG_TRACE_X86EMU) {
		X86EMU_trace_on();
	}
	// run VESA Interrupt
	runInt10();

	if (M.x86.R_AL != 0x4f) {
		DEBUG_PRINTF_VBE
		    ("%s: VBE Set Mode Function NOT supported! AL=%x\n",
		     __FUNCTION__, M.x86.R_AL);
		return -1;
	}

	if (M.x86.R_AH != 0x0) {
		DEBUG_PRINTF_VBE
		    ("%s: mode: %x VBE Set Mode Function Return Code NOT OK! AH=%x\n",
		     __FUNCTION__, mode_info->video_mode, M.x86.R_AH);
		return M.x86.R_AH;
	}
	return 0;
}

//VBE Function 08h
static uint8_t
vbe_set_palette_format(uint8_t format)
{
	vbe_prepare();
	// call VBE function 09h (Set/Get Palette Data Function)
	M.x86.R_EAX = 0x4f08;
	M.x86.R_BL = 0x00;	// set format
	M.x86.R_BH = format;

	DEBUG_PRINTF_VBE("%s: setting palette format: %d\n", __FUNCTION__,
			 format);

	// enable trace
	CHECK_DBG(DEBUG_TRACE_X86EMU) {
		X86EMU_trace_on();
	}
	// run VESA Interrupt
	runInt10();

	if (M.x86.R_AL != 0x4f) {
		DEBUG_PRINTF_VBE
		    ("%s: VBE Set Palette Format Function NOT supported! AL=%x\n",
		     __FUNCTION__, M.x86.R_AL);
		return -1;
	}

	if (M.x86.R_AH != 0x0) {
		DEBUG_PRINTF_VBE
		    ("%s: VBE Set Palette Format Function Return Code NOT OK! AH=%x\n",
		     __FUNCTION__, M.x86.R_AH);
		return M.x86.R_AH;
	}
	return 0;
}

// VBE Function 09h
static uint8_t
vbe_set_color(uint16_t color_number, uint32_t color_value)
{
	vbe_prepare();
	// call VBE function 09h (Set/Get Palette Data Function)
	M.x86.R_EAX = 0x4f09;
	M.x86.R_BL = 0x00;	// set color
	M.x86.R_CX = 0x01;	// set only one entry
	M.x86.R_DX = color_number;
	// ES:DI is address where color_value is stored, we store it at 2000:0000
	M.x86.R_ES = 0x2000;
	M.x86.R_DI = 0x0;

	// store color value at ES:DI
	out32le(biosmem + (M.x86.R_ES << 4) + M.x86.R_DI, color_value);

	DEBUG_PRINTF_VBE("%s: setting color #%x: 0x%04x\n", __FUNCTION__,
			 color_number, color_value);

	// enable trace
	CHECK_DBG(DEBUG_TRACE_X86EMU) {
		X86EMU_trace_on();
	}
	// run VESA Interrupt
	runInt10();

	if (M.x86.R_AL != 0x4f) {
		DEBUG_PRINTF_VBE
		    ("%s: VBE Set Palette Function NOT supported! AL=%x\n",
		     __FUNCTION__, M.x86.R_AL);
		return -1;
	}

	if (M.x86.R_AH != 0x0) {
		DEBUG_PRINTF_VBE
		    ("%s: VBE Set Palette Function Return Code NOT OK! AH=%x\n",
		     __FUNCTION__, M.x86.R_AH);
		return M.x86.R_AH;
	}
	return 0;
}

#if 0
static uint8_t
vbe_get_color(uint16_t color_number, uint32_t * color_value)
{
	vbe_prepare();
	// call VBE function 09h (Set/Get Palette Data Function)
	M.x86.R_EAX = 0x4f09;
	M.x86.R_BL = 0x00;	// get color
	M.x86.R_CX = 0x01;	// get only one entry
	M.x86.R_DX = color_number;
	// ES:DI is address where color_value is stored, we store it at 2000:0000
	M.x86.R_ES = 0x2000;
	M.x86.R_DI = 0x0;

	// enable trace
	CHECK_DBG(DEBUG_TRACE_X86EMU) {
		X86EMU_trace_on();
	}
	// run VESA Interrupt
	runInt10();

	if (M.x86.R_AL != 0x4f) {
		DEBUG_PRINTF_VBE
		    ("%s: VBE Set Palette Function NOT supported! AL=%x\n",
		     __FUNCTION__, M.x86.R_AL);
		return -1;
	}

	if (M.x86.R_AH != 0x0) {
		DEBUG_PRINTF_VBE
		    ("%s: VBE Set Palette Function Return Code NOT OK! AH=%x\n",
		     __FUNCTION__, M.x86.R_AH);
		return M.x86.R_AH;
	}
	// read color value from ES:DI
	*color_value = in32le(biosmem + (M.x86.R_ES << 4) + M.x86.R_DI);

	DEBUG_PRINTF_VBE("%s: getting color #%x --> 0x%04x\n", __FUNCTION__,
			 color_number, *color_value);

	return 0;
}
#endif

// VBE Function 15h
static uint8_t
vbe_get_ddc_info(vbe_ddc_info_t * ddc_info)
{
	vbe_prepare();
	// call VBE function 15h (DDC Info Function)
	M.x86.R_EAX = 0x4f15;
	M.x86.R_BL = 0x00;	// get DDC Info
	M.x86.R_CX = ddc_info->port_number;
	M.x86.R_ES = 0x0;
	M.x86.R_DI = 0x0;

	// enable trace
	CHECK_DBG(DEBUG_TRACE_X86EMU) {
		X86EMU_trace_on();
	}
	// run VESA Interrupt
	runInt10();

	if (M.x86.R_AL != 0x4f) {
		DEBUG_PRINTF_VBE
		    ("%s: VBE Get DDC Info Function NOT supported! AL=%x\n",
		     __FUNCTION__, M.x86.R_AL);
		return -1;
	}

	if (M.x86.R_AH != 0x0) {
		DEBUG_PRINTF_VBE
		    ("%s: port: %x VBE Get DDC Info Function Return Code NOT OK! AH=%x\n",
		     __FUNCTION__, ddc_info->port_number, M.x86.R_AH);
		return M.x86.R_AH;
	}
	// BH = approx. time in seconds to transfer one EDID block
	ddc_info->edid_transfer_time = M.x86.R_BH;
	// BL = DDC Level
	ddc_info->ddc_level = M.x86.R_BL;

	vbe_prepare();
	// call VBE function 15h (DDC Info Function)
	M.x86.R_EAX = 0x4f15;
	M.x86.R_BL = 0x01;	// read EDID
	M.x86.R_CX = ddc_info->port_number;
	M.x86.R_DX = 0x0;	// block number
	// ES:DI is address where EDID is stored, we store it at 2000:0000
	M.x86.R_ES = 0x2000;
	M.x86.R_DI = 0x0;

	// enable trace
	CHECK_DBG(DEBUG_TRACE_X86EMU) {
		X86EMU_trace_on();
	}
	// run VESA Interrupt
	runInt10();

	if (M.x86.R_AL != 0x4f) {
		DEBUG_PRINTF_VBE
		    ("%s: VBE Read EDID Function NOT supported! AL=%x\n",
		     __FUNCTION__, M.x86.R_AL);
		return -1;
	}

	if (M.x86.R_AH != 0x0) {
		DEBUG_PRINTF_VBE
		    ("%s: port: %x VBE Read EDID Function Return Code NOT OK! AH=%x\n",
		     __FUNCTION__, ddc_info->port_number, M.x86.R_AH);
		return M.x86.R_AH;
	}

	memcpy(ddc_info->edid_block_zero,
	       biosmem + (M.x86.R_ES << 4) + M.x86.R_DI,
	       sizeof(ddc_info->edid_block_zero));

	return 0;
}

uint32_t
vbe_get_info(uint8_t argc, char ** argv)
{
	uint8_t rval;
	static const uint8_t valid_edid_sig[] = {
		0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00
	};
	uint32_t i;

	if (argc < 4) {
		printf
		    ("Usage %s <vmem_base> <device_path> <address of screen_info_t>\n",
		     argv[0]);
		int i = 0;
		for (i = 0; i < argc; i++) {
			printf("argv[%d]: %s\n", i, argv[i]);
		}
		return -1;
	}
	// get a copy of input struct...
	screen_info_input_t input =
	    *((screen_info_input_t *) strtoul((char *) argv[4], 0, 16));
	// output is pointer to the address passed as argv[4]
	screen_info_t *output =
	    (screen_info_t *) strtoul((char *) argv[4], 0, 16);
	// zero output
	memset(output, 0, sizeof(screen_info_t));

	// argv[1] is address of virtual BIOS mem...
	// argv[2] is the size
	biosmem = (uint8_t *) strtoul(argv[1], 0, 16);
	biosmem_size = strtoul(argv[2], 0, 16);;
	if (biosmem_size < MIN_REQUIRED_VMEM_SIZE) {
		printf("Error: Not enough virtual memory: %x, required: %x!\n",
		       biosmem_size, MIN_REQUIRED_VMEM_SIZE);
		return -1;
	}
	// argv[3] is the device to open and use...
	if (dev_init((char *) argv[3]) != 0) {
		printf("Error initializing device!\n");
		return -1;
	}
	//setup interrupt handler
	X86EMU_intrFuncs intrFuncs[256];
	for (i = 0; i < 256; i++)
		intrFuncs[i] = handleInterrupt;
	X86EMU_setupIntrFuncs(intrFuncs);
	X86EMU_setupPioFuncs(&my_pio_funcs);
	X86EMU_setupMemFuncs(&my_mem_funcs);

	// set mem_base
	M.mem_base = (long) biosmem;
	M.mem_size = biosmem_size;
	DEBUG_PRINTF_VBE("membase set: %08x, size: %08x\n", (int) M.mem_base,
			 (int) M.mem_size);

	vbe_info_t info;
	rval = vbe_info(&info);
	if (rval != 0)
		return rval;

	DEBUG_PRINTF_VBE("VbeSignature: %s\n", info.signature);
	DEBUG_PRINTF_VBE("VbeVersion: 0x%04x\n", info.version);
	DEBUG_PRINTF_VBE("OemString: %s\n", info.oem_string_ptr);
	DEBUG_PRINTF_VBE("Capabilities:\n");
	DEBUG_PRINTF_VBE("\tDAC: %s\n",
			 (info.capabilities & 0x1) ==
			 0 ? "fixed 6bit" : "switchable 6/8bit");
	DEBUG_PRINTF_VBE("\tVGA: %s\n",
			 (info.capabilities & 0x2) ==
			 0 ? "compatible" : "not compatible");
	DEBUG_PRINTF_VBE("\tRAMDAC: %s\n",
			 (info.capabilities & 0x4) ==
			 0 ? "normal" : "use blank bit in Function 09h");

	// argv[4] may be a pointer with enough space to return screen_info_t
	// as input, it must contain a screen_info_input_t with the following content:
	// byte[0:3] = "DDC\0" (zero-terminated signature header)
	// byte[4:5] = reserved space for the return struct... just in case we ever change
	//             the struct and dont have reserved enough memory (and let's hope the struct
	//             never gets larger than 64KB)
	// byte[6] = monitor port number for DDC requests ("only" one byte... so lets hope we never have more than 255 monitors...
	// byte[7:8] = max. screen width (OF may want to limit this)
	// byte[9] = required color depth in bpp
	if (strncmp((char *) input.signature, "DDC", 4) != 0) {
		printf
		    ("%s: Invalid input signature! expected: %s, is: %s\n",
		     __FUNCTION__, "DDC", input.signature);
		return -1;
	}
	if (input.size_reserved != sizeof(screen_info_t)) {
		printf
		    ("%s: Size of return struct is wrong, required: %d, available: %d\n",
		     __FUNCTION__, (int) sizeof(screen_info_t),
		     input.size_reserved);
		return -1;
	}

	vbe_ddc_info_t ddc_info;
	ddc_info.port_number = input.monitor_number;
	vbe_get_ddc_info(&ddc_info);

#if 0
	DEBUG_PRINTF_VBE("DDC: edid_tranfer_time: %d\n",
			 ddc_info.edid_transfer_time);
	DEBUG_PRINTF_VBE("DDC: ddc_level: %x\n", ddc_info.ddc_level);
	DEBUG_PRINTF_VBE("DDC: EDID: \n");
	CHECK_DBG(DEBUG_VBE) {
		dump(ddc_info.edid_block_zero,
		     sizeof(ddc_info.edid_block_zero));
	}
#endif
	if (memcmp(ddc_info.edid_block_zero, valid_edid_sig, 8) != 0) {
		// invalid EDID signature... probably no monitor
		output->display_type = 0x0;
		return 0;
	} else if ((ddc_info.edid_block_zero[20] & 0x80) != 0) {
		// digital display
		output->display_type = 2;
	} else {
		// analog
		output->display_type = 1;
	}
	DEBUG_PRINTF_VBE("DDC: found display type %d\n", output->display_type);
	memcpy(output->edid_block_zero, ddc_info.edid_block_zero,
	       sizeof(ddc_info.edid_block_zero));
	i = 0;
	vbe_mode_info_t mode_info;
	vbe_mode_info_t best_mode_info;
	// initialize best_mode to 0
	memset(&best_mode_info, 0, sizeof(best_mode_info));
	while ((mode_info.video_mode = info.video_mode_list[i]) != 0xFFFF) {
		//DEBUG_PRINTF_VBE("%x: Mode: %04x\n", i, mode_info.video_mode);
		vbe_get_mode_info(&mode_info);
#if 0
		DEBUG_PRINTF_VBE("Video Mode 0x%04x available, %s\n",
				 mode_info.video_mode,
				 (mode_info.attributes & 0x1) ==
				 0 ? "not supported" : "supported");
		DEBUG_PRINTF_VBE("\tTTY: %s\n",
				 (mode_info.attributes & 0x4) ==
				 0 ? "no" : "yes");
		DEBUG_PRINTF_VBE("\tMode: %s %s\n",
				 (mode_info.attributes & 0x8) ==
				 0 ? "monochrome" : "color",
				 (mode_info.attributes & 0x10) ==
				 0 ? "text" : "graphics");
		DEBUG_PRINTF_VBE("\tVGA: %s\n",
				 (mode_info.attributes & 0x20) ==
				 0 ? "compatible" : "not compatible");
		DEBUG_PRINTF_VBE("\tWindowed Mode: %s\n",
				 (mode_info.attributes & 0x40) ==
				 0 ? "yes" : "no");
		DEBUG_PRINTF_VBE("\tFramebuffer: %s\n",
				 (mode_info.attributes & 0x80) ==
				 0 ? "no" : "yes");
		DEBUG_PRINTF_VBE("\tResolution: %dx%d\n",
				 mode_info.x_resolution,
				 mode_info.y_resolution);
		DEBUG_PRINTF_VBE("\tChar Size: %dx%d\n",
				 mode_info.x_charsize, mode_info.y_charsize);
		DEBUG_PRINTF_VBE("\tColor Depth: %dbpp\n",
				 mode_info.bits_per_pixel);
		DEBUG_PRINTF_VBE("\tMemory Model: 0x%x\n",
				 mode_info.memory_model);
		DEBUG_PRINTF_VBE("\tFramebuffer Offset: %08x\n",
				 mode_info.framebuffer_address);
#endif
		if ((mode_info.bits_per_pixel == input.color_depth)
		    && (mode_info.x_resolution <= input.max_screen_width)
		    && ((mode_info.attributes & 0x80) != 0)	// framebuffer mode
		    && ((mode_info.attributes & 0x10) != 0)	// graphics
		    && ((mode_info.attributes & 0x8) != 0)	// color
		    && (mode_info.x_resolution > best_mode_info.x_resolution))	// better than previous best_mode
		{
			// yiiiihaah... we found a new best mode
			memcpy(&best_mode_info, &mode_info, sizeof(mode_info));
		}
		i++;
	}

	if (best_mode_info.video_mode != 0) {
		DEBUG_PRINTF_VBE
		    ("Best Video Mode found: 0x%x, %dx%d, %dbpp, framebuffer_address: 0x%x\n",
		     best_mode_info.video_mode,
		     best_mode_info.x_resolution,
		     best_mode_info.y_resolution,
		     best_mode_info.bits_per_pixel,
		     best_mode_info.framebuffer_address);

		//printf("Mode Info Dump:");
		//dump(best_mode_info.mode_info_block, 64);

		// set the video mode
		vbe_set_mode(&best_mode_info);

		if ((info.capabilities & 0x1) != 0) {
			// switch to 8 bit palette format
			vbe_set_palette_format(8);
		}
		// setup a palette:
		// - first 216 colors are mixed colors for each component in 6 steps
		//   (6*6*6=216)
		// - then 10 shades of the three primary colors
		// - then 10 shades of grey
		// -------
		// = 256 colors
		//
		// - finally black is color 0 and white color FF (because SLOF expects it
		//   this way...)
		// this resembles the palette that the kernel/X Server seems to expect...

		uint8_t mixed_color_values[6] =
		    { 0xFF, 0xDA, 0xB3, 0x87, 0x54, 0x00 };
		uint8_t primary_color_values[10] =
		    { 0xF3, 0xE7, 0xCD, 0xC0, 0xA5, 0x96, 0x77, 0x66, 0x3F,
			0x27
		};
		uint8_t mc_size = sizeof(mixed_color_values);
		uint8_t prim_size = sizeof(primary_color_values);

		uint8_t curr_color_index;
		uint32_t curr_color;

		uint8_t r, g, b;
		// 216 mixed colors
		for (r = 0; r < mc_size; r++) {
			for (g = 0; g < mc_size; g++) {
				for (b = 0; b < mc_size; b++) {
					curr_color_index =
					    (r * mc_size * mc_size) +
					    (g * mc_size) + b;
					curr_color = 0;
					curr_color |= ((uint32_t) mixed_color_values[r]) << 16;	//red value
					curr_color |= ((uint32_t) mixed_color_values[g]) << 8;	//green value
					curr_color |= (uint32_t) mixed_color_values[b];	//blue value
					vbe_set_color(curr_color_index,
						      curr_color);
				}
			}
		}

		// 10 shades of each primary color
		// red
		for (r = 0; r < prim_size; r++) {
			curr_color_index = mc_size * mc_size * mc_size + r;
			curr_color = ((uint32_t) primary_color_values[r]) << 16;
			vbe_set_color(curr_color_index, curr_color);
		}
		//green
		for (g = 0; g < prim_size; g++) {
			curr_color_index =
			    mc_size * mc_size * mc_size + prim_size + g;
			curr_color = ((uint32_t) primary_color_values[g]) << 8;
			vbe_set_color(curr_color_index, curr_color);
		}
		//blue
		for (b = 0; b < prim_size; b++) {
			curr_color_index =
			    mc_size * mc_size * mc_size + prim_size * 2 + b;
			curr_color = (uint32_t) primary_color_values[b];
			vbe_set_color(curr_color_index, curr_color);
		}
		// 10 shades of grey
		for (i = 0; i < prim_size; i++) {
			curr_color_index =
			    mc_size * mc_size * mc_size + prim_size * 3 + i;
			curr_color = 0;
			curr_color |= ((uint32_t) primary_color_values[i]) << 16;	//red
			curr_color |= ((uint32_t) primary_color_values[i]) << 8;	//green
			curr_color |= ((uint32_t) primary_color_values[i]);	//blue
			vbe_set_color(curr_color_index, curr_color);
		}

		// SLOF is using color 0x0 (black) and 0xFF (white) to draw to the screen...
		vbe_set_color(0x00, 0x00000000);
		vbe_set_color(0xFF, 0x00FFFFFF);

		output->screen_width = best_mode_info.x_resolution;
		output->screen_height = best_mode_info.y_resolution;
		output->screen_linebytes = best_mode_info.linebytes;
		output->color_depth = best_mode_info.bits_per_pixel;
		output->framebuffer_address =
		    best_mode_info.framebuffer_address;
	} else {
		printf("%s: No suitable video mode found!\n", __FUNCTION__);
		//unset display_type...
		output->display_type = 0;
	}
	return 0;
}
