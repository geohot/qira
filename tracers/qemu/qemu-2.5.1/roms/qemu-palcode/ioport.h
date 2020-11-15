// Definitions for X86 IO port access.
//
// Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.
//
// This file copied (somewhat) intact from SeaBIOS.

#ifndef IOPORT_H
#define IOPORT_H

#define PORT_DMA_ADDR_2        0x0004
#define PORT_DMA_CNT_2         0x0005
#define PORT_DMA1_MASK_REG     0x000a
#define PORT_DMA1_MODE_REG     0x000b
#define PORT_DMA1_CLEAR_FF_REG 0x000c
#define PORT_DMA1_MASTER_CLEAR 0x000d
#define PORT_PIC1_CMD          0x0020
#define PORT_PIC1_DATA         0x0021
#define PORT_PIT_COUNTER0      0x0040
#define PORT_PIT_COUNTER1      0x0041
#define PORT_PIT_COUNTER2      0x0042
#define PORT_PIT_MODE          0x0043
#define PORT_PS2_DATA          0x0060
#define PORT_PS2_CTRLB         0x0061
#define PORT_PS2_STATUS        0x0064
#define PORT_CMOS_INDEX        0x0070
#define PORT_CMOS_DATA         0x0071
#define PORT_DIAG              0x0080
#define PORT_DMA_PAGE_2        0x0081
#define PORT_A20               0x0092
#define PORT_PIC2_CMD          0x00a0
#define PORT_PIC2_DATA         0x00a1
#define PORT_SMI_CMD           0x00b2
#define PORT_SMI_STATUS        0x00b3
#define PORT_DMA2_MASK_REG     0x00d4
#define PORT_DMA2_MODE_REG     0x00d6
#define PORT_DMA2_MASTER_CLEAR 0x00da
#define PORT_MATH_CLEAR        0x00f0
#define PORT_ATA2_CMD_BASE     0x0170
#define PORT_ATA1_CMD_BASE     0x01f0
#define PORT_LPT2              0x0278
#define PORT_SERIAL4           0x02e8
#define PORT_SERIAL2           0x02f8
#define PORT_ATA2_CTRL_BASE    0x0374
#define PORT_LPT1              0x0378
#define PORT_SERIAL3           0x03e8
#define PORT_ATA1_CTRL_BASE    0x03f4
#define PORT_FD_BASE           0x03f0
#define PORT_FD_DOR            0x03f2
#define PORT_FD_STATUS         0x03f4
#define PORT_FD_DATA           0x03f5
#define PORT_HD_DATA           0x03f6
#define PORT_FD_DIR            0x03f7
#define PORT_SERIAL1           0x03f8
#define PORT_PIC1_ELCR         0x04d0
#define PORT_PIC2_ELCR         0x04d1
#define PORT_PCI_CMD           0x0cf8
#define PORT_PCI_REBOOT        0x0cf9
#define PORT_PCI_DATA          0x0cfc
#define PORT_BIOS_DEBUG        0x0402
#define PORT_QEMU_CFG_CTL      0x0510
#define PORT_QEMU_CFG_DATA     0x0511
#define PORT_ACPI_PM_BASE      0xb000
#define PORT_SMB_BASE          0xb100
#define PORT_BIOS_APM          0x8900

// Serial port offsets
#define SEROFF_DATA    0
#define SEROFF_DLL     0
#define SEROFF_IER     1
#define SEROFF_DLH     1
#define SEROFF_IIR     2
#define SEROFF_LCR     3
#define SEROFF_LSR     5
#define SEROFF_MSR     6

// PORT_A20 bitdefs
#define A20_ENABLE_BIT 0x02

// PORT_CMOS_INDEX nmi disable bit
#define NMI_DISABLE_BIT 0x80

#endif // ioport.h
