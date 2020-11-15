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

#ifndef DEVICE_LIB_H
#define DEVICE_LIB_H

#include <stdint.h>
#include <cpu.h>
#include "of.h"
#include <stdio.h>

// a Expansion Header Struct as defined in Plug and Play BIOS Spec 1.0a Chapter 3.2
typedef struct {
	char signature[4];	// signature
	uint8_t structure_revision;
	uint8_t length;		// in 16 byte blocks
	uint16_t next_header_offset;	// offset to next Expansion Header as 16bit little-endian value, as offset from the start of the Expansion ROM
	uint8_t reserved;
	uint8_t checksum;	// the sum of all bytes of the Expansion Header must be 0
	uint32_t device_id;	// PnP Device ID as 32bit little-endian value
	uint16_t p_manufacturer_string;	//16bit little-endian offset from start of Expansion ROM
	uint16_t p_product_string;	//16bit little-endian offset from start of Expansion ROM
	uint8_t device_base_type;
	uint8_t device_sub_type;
	uint8_t device_if_type;
	uint8_t device_indicators;
	// the following vectors are all 16bit little-endian offsets from start of Expansion ROM
	uint16_t bcv;		// Boot Connection Vector
	uint16_t dv;		// Disconnect Vector
	uint16_t bev;		// Bootstrap Entry Vector
	uint16_t reserved_2;
	uint16_t sriv;		// Static Resource Information Vector
} __attribute__ ((__packed__)) exp_header_struct_t;

// a PCI Data Struct as defined in PCI 2.3 Spec Chapter 6.3.1.2
typedef struct {
	uint8_t signature[4];	// signature, the String "PCIR"
	uint16_t vendor_id;
	uint16_t device_id;
	uint16_t reserved;
	uint16_t pci_ds_length;	// PCI Data Structure Length, 16bit little-endian value
	uint8_t pci_ds_revision;
	uint8_t class_code[3];
	uint16_t img_length;	// length of the Exp.ROM Image, 16bit little-endian value in 512 bytes
	uint16_t img_revision;
	uint8_t code_type;
	uint8_t indicator;
	uint16_t reserved_2;
} __attribute__ ((__packed__)) pci_data_struct_t;

typedef struct {
	uint8_t bus;
	uint8_t devfn;
	uint64_t puid;
	phandle_t phandle;
	ihandle_t ihandle;
	// store the address of the BAR that is used to simulate
	// legacy VGA memory accesses
	uint64_t vmem_addr;
	uint64_t vmem_size;
	// used to buffer I/O Accesses, that do not access the I/O Range of the device...
	// 64k might be overkill, but we can buffer all I/O accesses...
	uint8_t io_buffer[64 * 1024];
	uint16_t pci_vendor_id;
	uint16_t pci_device_id;
	// translated address of the "PC-Compatible" Expansion ROM Image for this device
	uint64_t img_addr;
	uint32_t img_size;	// size of the Expansion ROM Image (read from the PCI Data Structure)
} device_t;

typedef struct {
	uint8_t info;
	uint8_t bus;
	uint8_t devfn;
	uint8_t cfg_space_offset;
	uint64_t address;
	uint64_t address_offset;
	uint64_t size;
} __attribute__ ((__packed__)) translate_address_t;

// array to store address translations for this
// device. Needed for faster address translation, so
// not every I/O or Memory Access needs to call translate_address_dev
// and access the device tree
// 6 BARs, 1 Exp. ROM, 1 Cfg.Space, and 3 Legacy
// translations are supported... this should be enough for
// most devices... for VGA it is enough anyways...
translate_address_t translate_address_array[11];

// index of last translate_address_array entry
// set by get_dev_addr_info function
uint8_t taa_last_entry;

device_t bios_device;

uint8_t dev_init(char *device_name);
// NOTE: for dev_check_exprom to work, dev_init MUST be called first!
uint8_t dev_check_exprom(void);

uint8_t dev_translate_address(uint64_t * addr);

/* endianness swap functions for 16 and 32 bit words
 * copied from axon_pciconfig.c
 */
static inline void
out32le(void *addr, uint32_t val)
{
	asm volatile ("stwbrx  %0, 0, %1"::"r" (val), "r"(addr));
}

static inline uint32_t
in32le(void *addr)
{
	uint32_t val;
	const uint32_t *zaddr = addr;
	asm volatile ("lwbrx %0, %y1" : "=r"(val) : "Z"(*zaddr));
	return val;
}

static inline void
out16le(void *addr, uint16_t val)
{
	asm volatile ("sthbrx  %0, 0, %1"::"r" (val), "r"(addr));
}

static inline uint16_t
in16le(void *addr)
{
	uint16_t val;
	const uint16_t *zaddr = addr;
	asm volatile ("lhbrx %0, %y1" : "=r"(val) : "Z"(*zaddr));
	return val;
}

/* debug function, dumps HID1 and HID4 to detect wether caches are on/off */
static inline void
dumpHID(void)
{
	uint64_t hid;
	//HID1 = 1009
	__asm__ __volatile__("mfspr %0, 1009":"=r"(hid));
	printf("HID1: %016llx\n", hid);
	//HID4 = 1012
	__asm__ __volatile__("mfspr %0, 1012":"=r"(hid));
	printf("HID4: %016llx\n", hid);
}

#endif
