/*******************************************************************************

  Intel(R) 82576 Virtual Function Linux driver
  Copyright(c) 1999 - 2008 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  Linux NICS <linux.nics@intel.com>
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

FILE_LICENCE ( GPL2_ONLY );

/* glue for the OS-dependent part of igbvf
 * includes register access macros
 */

#ifndef _IGBVF_OSDEP_H_
#define _IGBVF_OSDEP_H_

#define u8         unsigned char
#define bool       boolean_t
#define dma_addr_t unsigned long
#define __le16     uint16_t
#define __le32     uint32_t
#define __le64     uint64_t

#define __iomem
#define __devinit
#define ____cacheline_aligned_in_smp

#define msleep(x) mdelay(x)

#define ETH_FCS_LEN 4

typedef int spinlock_t;
typedef enum {
    false = 0,
    true = 1
} boolean_t;

#define usec_delay(x) udelay(x)
#define msec_delay(x) mdelay(x)
#define msec_delay_irq(x) mdelay(x)

#define PCI_COMMAND_REGISTER   PCI_COMMAND
#define CMD_MEM_WRT_INVALIDATE PCI_COMMAND_INVALIDATE
#define ETH_ADDR_LEN           ETH_ALEN


#define DEBUGOUT(S) if (0) { printf(S); }
#define DEBUGOUT1(S, A...) if (0) { printf(S, A); }

#define DEBUGFUNC(F) DEBUGOUT(F "\n")
#define DEBUGOUT2 DEBUGOUT1
#define DEBUGOUT3 DEBUGOUT2
#define DEBUGOUT7 DEBUGOUT3

#define E1000_WRITE_REG(a, reg, value) do { \
    writel((value), ((a)->hw_addr + reg)); } while (0)

#define E1000_READ_REG(a, reg) (readl((a)->hw_addr + reg))

#define E1000_WRITE_REG_ARRAY(a, reg, offset, value) do { \
    writel((value), ((a)->hw_addr + reg + ((offset) << 2))); } while (0)

#define E1000_READ_REG_ARRAY(a, reg, offset) ( \
    readl((a)->hw_addr + reg + ((offset) << 2)))

#define E1000_READ_REG_ARRAY_DWORD E1000_READ_REG_ARRAY
#define E1000_WRITE_REG_ARRAY_DWORD E1000_WRITE_REG_ARRAY

#define E1000_WRITE_REG_ARRAY_WORD(a, reg, offset, value) ( \
    writew((value), ((a)->hw_addr + reg + ((offset) << 1))))

#define E1000_READ_REG_ARRAY_WORD(a, reg, offset) ( \
    readw((a)->hw_addr + reg + ((offset) << 1)))

#define E1000_WRITE_REG_ARRAY_BYTE(a, reg, offset, value) ( \
    writeb((value), ((a)->hw_addr + reg + (offset))))

#define E1000_READ_REG_ARRAY_BYTE(a, reg, offset) ( \
    readb((a)->hw_addr + reg + (offset)))

#define E1000_WRITE_REG_IO(a, reg, offset) do { \
    outl(reg, ((a)->io_base));                  \
    outl(offset, ((a)->io_base + 4));      } while(0)

#define E1000_WRITE_FLUSH(a) E1000_READ_REG(a, E1000_STATUS)

#define E1000_WRITE_FLASH_REG(a, reg, value) ( \
    writel((value), ((a)->flash_address + reg)))

#define E1000_WRITE_FLASH_REG16(a, reg, value) ( \
    writew((value), ((a)->flash_address + reg)))

#define E1000_READ_FLASH_REG(a, reg) (readl((a)->flash_address + reg))

#define E1000_READ_FLASH_REG16(a, reg) (readw((a)->flash_address + reg))

#endif /* _IGBVF_OSDEP_H_ */
