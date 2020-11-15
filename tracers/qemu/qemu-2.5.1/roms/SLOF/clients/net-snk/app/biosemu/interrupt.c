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

#include <rtas.h>

#include "biosemu.h"
#include "mem.h"
#include "device.h"
#include "debug.h"
#include "interrupt.h"

#include <x86emu/x86emu.h>
#include <x86emu/prim_ops.h>



//setup to run the code at the address, that the Interrupt Vector points to...
static void
setupInt(int intNum)
{
	DEBUG_PRINTF_INTR("%s(%x): executing interrupt handler @%08x\n",
			  __FUNCTION__, intNum, my_rdl(intNum * 4));
	// push current R_FLG... will be popped by IRET
	push_word((u16) M.x86.R_FLG);
	CLEAR_FLAG(F_IF);
	CLEAR_FLAG(F_TF);
	// push current CS:IP to the stack, will be popped by IRET
	push_word(M.x86.R_CS);
	push_word(M.x86.R_IP);
	// set CS:IP to the interrupt handler address... so the next executed instruction will
	// be the interrupt handler
	M.x86.R_CS = my_rdw(intNum * 4 + 2);
	M.x86.R_IP = my_rdw(intNum * 4);
}

// handle int10 (VGA BIOS Interrupt)
static void
handleInt10(void)
{
	// the data for INT10 is stored in BDA (0000:0400h) offset 49h-66h
	// function number in AH
	//DEBUG_PRINTF_CS_IP("%s:\n", __FUNCTION__);
	//x86emu_dump_xregs();
	//if ((M.x86.R_IP == 0x32c2) && (M.x86.R_SI == 0x1ce2)){
	//X86EMU_trace_on();
	//M.x86.debug &= ~DEBUG_DECODE_NOPRINT_F;
	//}
	switch (M.x86.R_AH) {
	case 0x00:
		// set video mode
		// BDA offset 49h is current video mode
		my_wrb(0x449, M.x86.R_AL);
		if (M.x86.R_AL > 7)
			M.x86.R_AL = 0x20;
		else if (M.x86.R_AL == 6)
			M.x86.R_AL = 0x3f;
		else
			M.x86.R_AL = 0x30;
		break;
	case 0x01:
		// set cursor shape
		// ignore
		break;
	case 0x02:
		// set cursor position
		// BH: pagenumber, DX: cursor_pos (DH:row, DL:col)
		// BDA offset 50h-60h are 8 cursor position words for
		// eight possible video pages
		my_wrw(0x450 + (M.x86.R_BH * 2), M.x86.R_DX);
		break;
	case 0x03:
		//get cursor position
		// BH: pagenumber
		// BDA offset 50h-60h are 8 cursor position words for
		// eight possible video pages
		M.x86.R_AX = 0;
		M.x86.R_CH = 0;	// start scan line ???
		M.x86.R_CL = 0;	// end scan line ???
		M.x86.R_DX = my_rdw(0x450 + (M.x86.R_BH * 2));
		break;
	case 0x05:
		// set active page
		// BDA offset 62h is current page number
		my_wrb(0x462, M.x86.R_AL);
		break;
	case 0x06:
		//scroll up windows
		break;
	case 0x07:
		//scroll down windows
		break;
	case 0x08:
		//read character and attribute at position
		M.x86.R_AH = 0x07;	// white-on-black
		M.x86.R_AL = 0x20;	// a space...
		break;
	case 0x09:
		// write character and attribute
		//AL: char, BH: page number, BL: attribute, CX: number of times to write
		//BDA offset 62h is current page number
		CHECK_DBG(DEBUG_PRINT_INT10) {
			uint32_t i = 0;
			if (M.x86.R_BH == my_rdb(0x462)) {
				for (i = 0; i < M.x86.R_CX; i++)
					printf("%c", M.x86.R_AL);
			}
		}
		break;
	case 0x0a:
		// write character
		//AL: char, BH: page number, BL: attribute, CX: number of times to write
		//BDA offset 62h is current page number
		CHECK_DBG(DEBUG_PRINT_INT10) {
			uint32_t i = 0;
			if (M.x86.R_BH == my_rdb(0x462)) {
				for (i = 0; i < M.x86.R_CX; i++)
					printf("%c", M.x86.R_AL);
			}
		}
		break;
	case 0x0e:
		// teletype output: write character and advance cursor...
		//AL: char, BH: page number, BL: attribute
		//BDA offset 62h is current page number
		CHECK_DBG(DEBUG_PRINT_INT10) {
			// we ignore the pagenumber on this call...
			//if (M.x86.R_BH == my_rdb(0x462))
			{
				printf("%c", M.x86.R_AL);
				// for debugging, to read all lines
				//if (M.x86.R_AL == 0xd) // carriage return
				//      printf("\n");
			}
		}
		break;
	case 0x0f:
		// get video mode
		// BDA offset 49h is current video mode
		// BDA offset 62h is current page number
		// BDA offset 4ah is columns on screen
		M.x86.R_AH = 80;	//number of character columns... we hardcode it to 80
		M.x86.R_AL = my_rdb(0x449);
		M.x86.R_BH = my_rdb(0x462);
		break;
	default:
		printf("%s(): unknown function (%x) for int10 handler.\n",
		       __FUNCTION__, M.x86.R_AH);
		DEBUG_PRINTF_INTR("AX=%04x BX=%04x CX=%04x DX=%04x\n",
				  M.x86.R_AX, M.x86.R_BX, M.x86.R_CX,
				  M.x86.R_DX);
		HALT_SYS();
		break;
	}
}

// this table translates ASCII chars into their XT scan codes:
static uint8_t keycode_table[256] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// 0 - 7
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// 8 - 15
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// 16 - 23
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// 24 - 31
	0x39, 0x02, 0x28, 0x04, 0x05, 0x06, 0x08, 0x28,	// 32 - 39
	0x0a, 0x0b, 0x09, 0x2b, 0x33, 0x0d, 0x34, 0x35,	// 40 - 47
	0x0b, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,	// 48 - 55
	0x09, 0x0a, 0x27, 0x27, 0x33, 0x2b, 0x34, 0x35,	// 56 - 63
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// 64 - 71
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// 72 - 79
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// 80 - 87
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// 88 - 95
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// 96 - 103
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// 104 - 111
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// 112 - 119
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// 120 - 127
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// ...
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static void
translate_keycode(uint64_t * keycode)
{
	uint8_t scan_code = 0;
	uint8_t char_code = 0;
	if (*keycode < 256) {
		scan_code = keycode_table[*keycode];
		char_code = (uint8_t) * keycode & 0xff;
	} else {
		switch (*keycode) {
		case 0x1b50:
			// F1
			scan_code = 0x3b;
			char_code = 0x0;
			break;
		default:
			printf("%s(): unknown multibyte keycode: %llx\n",
			       __FUNCTION__, *keycode);
			break;
		}
	}
	//assemble scan/char code in keycode
	*keycode = (uint64_t) ((((uint16_t) scan_code) << 8) | char_code);
}

// handle int16 (Keyboard BIOS Interrupt)
static void
handleInt16(void)
{
	// keyboard buffer is in BIOS Memory Area:
	// offset 0x1a (WORD) pointer to next char in keybuffer
	// offset 0x1c (WORD) pointer to next insert slot in keybuffer
	// offset 0x1e-0x3e: 16 WORD Ring Buffer
	// since we currently always read the char from the FW buffer,
	// we misuse the ring buffer, we use it as pointer to a uint64_t that stores
	// multi-byte keys (e.g. special keys in VT100 terminal)
	// and as long as a key is available (not 0) we dont read further keys
	uint64_t *keycode = (uint64_t *) (M.mem_base + 0x41e);
	int8_t c;
	// function number in AH
	DEBUG_PRINTF_INTR("%s(): Keyboard Interrupt: function: %x.\n",
			  __FUNCTION__, M.x86.R_AH);
	DEBUG_PRINTF_INTR("AX=%04x BX=%04x CX=%04x DX=%04x\n", M.x86.R_AX,
			  M.x86.R_BX, M.x86.R_CX, M.x86.R_DX);
	switch (M.x86.R_AH) {
	case 0x00:
		// get keystroke
		if (*keycode) {
			M.x86.R_AX = (uint16_t) * keycode;
			// clear keycode
			*keycode = 0;
		} else {
			M.x86.R_AH = 0x61;	// scancode for space key
			M.x86.R_AL = 0x20;	// a space
		}
		break;
	case 0x01:
		// check keystroke
		// ZF set = no keystroke
		// read first byte of key code
		if (*keycode) {
			// already read, but not yet taken
			CLEAR_FLAG(F_ZF);
			M.x86.R_AX = (uint16_t) * keycode;
		} else {
			c = getchar();
			if (c == -1) {
				// no key available
				SET_FLAG(F_ZF);
			} else {
				*keycode = c;

				// since after an ESC it may take a while to receive the next char,
				// we send something that is not shown on the screen, and then try to get
				// the next char
				// TODO: only after ESC?? what about other multibyte keys
				printf("tt%c%c", 0x08, 0x08);	// 0x08 == Backspace

				while ((c = getchar()) != -1) {
					*keycode = (*keycode << 8) | c;
					DEBUG_PRINTF(" key read: %0llx\n",
						     *keycode);
				}
				translate_keycode(keycode);
				DEBUG_PRINTF(" translated key: %0llx\n",
					     *keycode);
				if (*keycode == 0) {
					//not found
					SET_FLAG(F_ZF);
				} else {
					CLEAR_FLAG(F_ZF);
					M.x86.R_AX = (uint16_t) * keycode;
					//X86EMU_trace_on();
					//M.x86.debug &= ~DEBUG_DECODE_NOPRINT_F;
				}
			}
		}
		break;
	default:
		printf("%s(): unknown function (%x) for int16 handler.\n",
		       __FUNCTION__, M.x86.R_AH);
		DEBUG_PRINTF_INTR("AX=%04x BX=%04x CX=%04x DX=%04x\n",
				  M.x86.R_AX, M.x86.R_BX, M.x86.R_CX,
				  M.x86.R_DX);
		HALT_SYS();
		break;
	}
}

// handle int1a (PCI BIOS Interrupt)
static void
handleInt1a(void)
{
	// function number in AX
	uint8_t bus, devfn, offs;
	switch (M.x86.R_AX) {
	case 0xb101:
		// Installation check
		CLEAR_FLAG(F_CF);	// clear CF
		M.x86.R_EDX = 0x20494350;	// " ICP" endian swapped "PCI "
		M.x86.R_AL = 0x1;	// Config Space Mechanism 1 supported
		M.x86.R_BX = 0x0210;	// PCI Interface Level Version 2.10
		M.x86.R_CL = 0xff;	// number of last PCI Bus in system TODO: check!
		break;
	case 0xb102:
		// Find PCI Device
		// NOTE: we currently only allow the device to find itself...
		// it SHOULD be all we ever need...
		// device_id in CX, vendor_id in DX
		// device index in SI (i.e. if multiple devices with same vendor/device id
		// are connected). We currently only support device index 0
		DEBUG_PRINTF_INTR("%s(): function: %x: PCI Find Device\n",
				  __FUNCTION__, M.x86.R_AX);
		if ((M.x86.R_CX == bios_device.pci_device_id)
		    && (M.x86.R_DX == bios_device.pci_vendor_id)
		    // device index must be 0
		    && (M.x86.R_SI == 0)) {
			CLEAR_FLAG(F_CF);
			M.x86.R_AH = 0x00;	// return code: success
			M.x86.R_BH = bios_device.bus;
			M.x86.R_BL = bios_device.devfn;
			DEBUG_PRINTF_INTR
			    ("%s(): function %x: PCI Find Device --> 0x%04x\n",
			     __FUNCTION__, M.x86.R_AX, M.x86.R_BX);
		} else {
			DEBUG_PRINTF_INTR
			    ("%s(): function %x: invalid device/vendor/device index! (%04x/%04x/%02x expected: %04x/%04x/0) \n",
			     __FUNCTION__, M.x86.R_AX, M.x86.R_CX, M.x86.R_DX,
			     M.x86.R_SI, bios_device.pci_device_id,
			     bios_device.pci_vendor_id);
			SET_FLAG(F_CF);
			M.x86.R_AH = 0x86;	// return code: device not found
		}
		break;
	case 0xb108:		//read configuration byte
	case 0xb109:		//read configuration word
	case 0xb10a:		//read configuration dword
		bus = M.x86.R_BH;
		devfn = M.x86.R_BL;
		offs = M.x86.R_DI;
		if ((bus != bios_device.bus)
		    || (devfn != bios_device.devfn)) {
			// fail accesses to any device but ours...
			printf
			    ("%s(): Config read access invalid! bus: %x (%x), devfn: %x (%x), offs: %x\n",
			     __FUNCTION__, bus, bios_device.bus, devfn,
			     bios_device.devfn, offs);
			SET_FLAG(F_CF);
			M.x86.R_AH = 0x87;	//return code: bad pci register
			HALT_SYS();
			return;
		} else {
			switch (M.x86.R_AX) {
			case 0xb108:
				M.x86.R_CL =
				    (uint8_t) rtas_pci_config_read(bios_device.
								   puid, 1,
								   bus, devfn,
								   offs);
				DEBUG_PRINTF_INTR
				    ("%s(): function %x: PCI Config Read @%02x --> 0x%02x\n",
				     __FUNCTION__, M.x86.R_AX, offs,
				     M.x86.R_CL);
				break;
			case 0xb109:
				M.x86.R_CX =
				    (uint16_t) rtas_pci_config_read(bios_device.
								    puid, 2,
								    bus, devfn,
								    offs);
				DEBUG_PRINTF_INTR
				    ("%s(): function %x: PCI Config Read @%02x --> 0x%04x\n",
				     __FUNCTION__, M.x86.R_AX, offs,
				     M.x86.R_CX);
				break;
			case 0xb10a:
				M.x86.R_ECX =
				    (uint32_t) rtas_pci_config_read(bios_device.
								    puid, 4,
								    bus, devfn,
								    offs);
				DEBUG_PRINTF_INTR
				    ("%s(): function %x: PCI Config Read @%02x --> 0x%08x\n",
				     __FUNCTION__, M.x86.R_AX, offs,
				     M.x86.R_ECX);
				break;
			}
			CLEAR_FLAG(F_CF);
			M.x86.R_AH = 0x0;	// return code: success
		}
		break;
	case 0xb10b:		//write configuration byte
	case 0xb10c:		//write configuration word
	case 0xb10d:		//write configuration dword
		bus = M.x86.R_BH;
		devfn = M.x86.R_BL;
		offs = M.x86.R_DI;
		if ((bus != bios_device.bus)
		    || (devfn != bios_device.devfn)) {
			// fail accesses to any device but ours...
			printf
			    ("%s(): Config read access invalid! bus: %x (%x), devfn: %x (%x), offs: %x\n",
			     __FUNCTION__, bus, bios_device.bus, devfn,
			     bios_device.devfn, offs);
			SET_FLAG(F_CF);
			M.x86.R_AH = 0x87;	//return code: bad pci register
			HALT_SYS();
			return;
		} else {
			switch (M.x86.R_AX) {
			case 0xb10b:
				rtas_pci_config_write(bios_device.puid, 1, bus,
						      devfn, offs, M.x86.R_CL);
				DEBUG_PRINTF_INTR
				    ("%s(): function %x: PCI Config Write @%02x <-- 0x%02x\n",
				     __FUNCTION__, M.x86.R_AX, offs,
				     M.x86.R_CL);
				break;
			case 0xb10c:
				rtas_pci_config_write(bios_device.puid, 2, bus,
						      devfn, offs, M.x86.R_CX);
				DEBUG_PRINTF_INTR
				    ("%s(): function %x: PCI Config Write @%02x <-- 0x%04x\n",
				     __FUNCTION__, M.x86.R_AX, offs,
				     M.x86.R_CX);
				break;
			case 0xb10d:
				rtas_pci_config_write(bios_device.puid, 4, bus,
						      devfn, offs, M.x86.R_ECX);
				DEBUG_PRINTF_INTR
				    ("%s(): function %x: PCI Config Write @%02x <-- 0x%08x\n",
				     __FUNCTION__, M.x86.R_AX, offs,
				     M.x86.R_ECX);
				break;
			}
			CLEAR_FLAG(F_CF);
			M.x86.R_AH = 0x0;	// return code: success
		}
		break;
	default:
		printf("%s(): unknown function (%x) for int1a handler.\n",
		       __FUNCTION__, M.x86.R_AX);
		DEBUG_PRINTF_INTR("AX=%04x BX=%04x CX=%04x DX=%04x\n",
				  M.x86.R_AX, M.x86.R_BX, M.x86.R_CX,
				  M.x86.R_DX);
		HALT_SYS();
		break;
	}
}

// main Interrupt Handler routine, should be registered as x86emu interrupt handler
void
handleInterrupt(int intNum)
{
	uint8_t int_handled = 0;
#ifndef DEBUG_PRINT_INT10
	// this printf makes output by int 10 unreadable...
	// so we only enable it, if int10 print is disabled
	DEBUG_PRINTF_INTR("%s(%x)\n", __FUNCTION__, intNum);
#endif
	switch (intNum) {
	case 0x10:		//BIOS video interrupt
	case 0x42:		// INT 10h relocated by EGA/VGA BIOS
	case 0x6d:		// INT 10h relocated by VGA BIOS
		// get interrupt vector from IDT (4 bytes per Interrupt starting at address 0
		if ((my_rdl(intNum * 4) == 0xF000F065) ||	//F000:F065 is default BIOS interrupt handler address
		    (my_rdl(intNum * 4) == 0xF4F4F4F4))	//invalid
		{
#if 0
			// ignore interrupt...
			DEBUG_PRINTF_INTR
			    ("%s(%x): invalid interrupt Vector (%08x) found, interrupt ignored...\n",
			     __FUNCTION__, intNum, my_rdl(intNum * 4));
			DEBUG_PRINTF_INTR("AX=%04x BX=%04x CX=%04x DX=%04x\n",
					  M.x86.R_AX, M.x86.R_BX, M.x86.R_CX,
					  M.x86.R_DX);
			//HALT_SYS();
#endif
			handleInt10();
			int_handled = 1;
		}
		break;
	case 0x16:
		// Keyboard BIOS Interrupt
		handleInt16();
		int_handled = 1;
		break;
	case 0x1a:
		// PCI BIOS Interrupt
		handleInt1a();
		int_handled = 1;
		break;
	default:
		printf("Interrupt %#x (Vector: %x) not implemented\n", intNum,
		       my_rdl(intNum * 4));
		DEBUG_PRINTF_INTR("AX=%04x BX=%04x CX=%04x DX=%04x\n",
				  M.x86.R_AX, M.x86.R_BX, M.x86.R_CX,
				  M.x86.R_DX);
		int_handled = 1;
		HALT_SYS();
		break;
	}
	// if we did not handle the interrupt, jump to the interrupt vector...
	if (!int_handled) {
		setupInt(intNum);
	}
}

// prepare and execute Interrupt 10 (VGA Interrupt)
void
runInt10()
{
	// Initialize stack and data segment
	M.x86.R_SS = STACK_SEGMENT;
	M.x86.R_DS = DATA_SEGMENT;
	M.x86.R_SP = STACK_START_OFFSET;

	// push a HLT instruction and a pointer to it onto the stack
	// any return will pop the pointer and jump to the HLT, thus
	// exiting (more or less) cleanly
	push_word(0xf4f4);	//F4=HLT
	//push_word(M.x86.R_SS);
	//push_word(M.x86.R_SP + 2);

	// setupInt will push the current CS and IP to the stack to return to it,
	// but we want to halt, so set CS:IP to the HLT instruction we just pushed
	// to the stack
	M.x86.R_CS = M.x86.R_SS;
	M.x86.R_IP = M.x86.R_SP;	// + 4;

	CHECK_DBG(DEBUG_TRACE_X86EMU) {
		X86EMU_trace_on();
	}
	CHECK_DBG(DEBUG_JMP) {
		M.x86.debug |= DEBUG_TRACEJMP_REGS_F;
		M.x86.debug |= DEBUG_TRACEJMP_REGS_F;
		M.x86.debug |= DEBUG_TRACECALL_F;
		M.x86.debug |= DEBUG_TRACECALL_REGS_F;
	}
	setupInt(0x10);
	DEBUG_PRINTF_INTR("%s(): starting execution of INT10...\n",
			  __FUNCTION__);
	X86EMU_exec();
	DEBUG_PRINTF_INTR("%s(): execution finished\n", __FUNCTION__);
}

// prepare and execute Interrupt 13 (Disk Interrupt)
void
runInt13(void)
{
	// Initialize stack and data segment
	M.x86.R_SS = STACK_SEGMENT;
	M.x86.R_DS = DATA_SEGMENT;
	M.x86.R_SP = STACK_START_OFFSET;

	// push a HLT instruction and a pointer to it onto the stack
	// any return will pop the pointer and jump to the HLT, thus
	// exiting (more or less) cleanly
	push_word(0xf4f4);	//F4=HLT
	//push_word(M.x86.R_SS);
	//push_word(M.x86.R_SP + 2);

	// setupInt will push the current CS and IP to the stack to return to it,
	// but we want to halt, so set CS:IP to the HLT instruction we just pushed
	// to the stack
	M.x86.R_CS = M.x86.R_SS;
	M.x86.R_IP = M.x86.R_SP;

	CHECK_DBG(DEBUG_TRACE_X86EMU) {
		X86EMU_trace_on();
	}
	CHECK_DBG(DEBUG_JMP) {
		M.x86.debug |= DEBUG_TRACEJMP_REGS_F;
		M.x86.debug |= DEBUG_TRACEJMP_REGS_F;
		M.x86.debug |= DEBUG_TRACECALL_F;
		M.x86.debug |= DEBUG_TRACECALL_REGS_F;
	}

	setupInt(0x13);
	DEBUG_PRINTF_INTR("%s(): starting execution of INT13...\n",
			  __FUNCTION__);
	X86EMU_exec();
	DEBUG_PRINTF_INTR("%s(): execution finished\n", __FUNCTION__);
}
