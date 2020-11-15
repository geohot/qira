/**************************************************************************
 *
 * Etherboot driver for Level 5 Etherfabric network cards
 *
 * Written by Michael Brown <mbrown@fensystems.co.uk>
 *
 * Copyright Fen Systems Ltd. 2005
 * Copyright Level 5 Networks Inc. 2005
 *
 * This software may be used and distributed according to the terms of
 * the GNU General Public License (GPL), incorporated herein by
 * reference.  Drivers based on or derived from this code fall under
 * the GPL and must retain the authorship, copyright and license
 * notice.
 *
 **************************************************************************
 */

FILE_LICENCE ( GPL_ANY );

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <byteswap.h>
#include <ipxe/io.h>
#include <ipxe/pci.h>
#include <ipxe/malloc.h>
#include <ipxe/ethernet.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/timer.h>
#include <mii.h>
#include "etherfabric.h"
#include "etherfabric_nic.h"

/**************************************************************************
 *
 * Constants and macros
 *
 **************************************************************************
 */

#define EFAB_REGDUMP(...)
#define EFAB_TRACE(...) DBGP(__VA_ARGS__)

// printf() is not allowed within drivers.  Use DBG() instead.
#define EFAB_LOG(...) DBG(__VA_ARGS__)
#define EFAB_ERR(...) DBG(__VA_ARGS__)

#define FALCON_USE_IO_BAR 0

#define HZ 100
#define EFAB_BYTE 1

/**************************************************************************
 *
 * Hardware data structures and sizing
 *
 **************************************************************************
 */
extern int __invalid_queue_size;
#define FQS(_prefix, _x)					\
	( ( (_x) == 512 ) ? _prefix ## _SIZE_512 :		\
	  ( ( (_x) == 1024 ) ? _prefix ## _SIZE_1K :		\
	    ( ( (_x) == 2048 ) ? _prefix ## _SIZE_2K :		\
	      ( ( (_x) == 4096) ? _prefix ## _SIZE_4K :		\
		__invalid_queue_size ) ) ) )


#define EFAB_MAX_FRAME_LEN(mtu)				\
	( ( ( ( mtu ) + 4/* FCS */ ) + 7 ) & ~7 )

/**************************************************************************
 *
 * GMII routines
 *
 **************************************************************************
 */

static void falcon_mdio_write (struct efab_nic *efab, int device,
			       int location, int value );
static int falcon_mdio_read ( struct efab_nic *efab, int device, int location );

/* GMII registers */
#define GMII_PSSR		0x11	/* PHY-specific status register */

/* Pseudo extensions to the link partner ability register */
#define LPA_EF_1000FULL		0x00020000
#define LPA_EF_1000HALF		0x00010000
#define LPA_EF_10000FULL		0x00040000
#define LPA_EF_10000HALF		0x00080000

#define LPA_EF_1000		( LPA_EF_1000FULL | LPA_EF_1000HALF )
#define LPA_EF_10000               ( LPA_EF_10000FULL | LPA_EF_10000HALF )
#define LPA_EF_DUPLEX		( LPA_10FULL | LPA_100FULL | LPA_EF_1000FULL | \
				  LPA_EF_10000FULL )

/* Mask of bits not associated with speed or duplexity. */
#define LPA_OTHER		~( LPA_10FULL | LPA_10HALF | LPA_100FULL | \
				   LPA_100HALF | LPA_EF_1000FULL | LPA_EF_1000HALF )

/* PHY-specific status register */
#define PSSR_LSTATUS		0x0400	/* Bit 10 - link status */

/**
 * Retrieve GMII autonegotiation advertised abilities
 *
 */
static unsigned int
gmii_autoneg_advertised ( struct efab_nic *efab )
{
	unsigned int mii_advertise;
	unsigned int gmii_advertise;

	/* Extended bits are in bits 8 and 9 of MII_CTRL1000 */
	mii_advertise = falcon_mdio_read ( efab, 0, MII_ADVERTISE );
	gmii_advertise = ( ( falcon_mdio_read ( efab, 0, MII_CTRL1000 ) >> 8 )
			   & 0x03 );
	return ( ( gmii_advertise << 16 ) | mii_advertise );
}

/**
 * Retrieve GMII autonegotiation link partner abilities
 *
 */
static unsigned int
gmii_autoneg_lpa ( struct efab_nic *efab )
{
	unsigned int mii_lpa;
	unsigned int gmii_lpa;

	/* Extended bits are in bits 10 and 11 of MII_STAT1000 */
	mii_lpa = falcon_mdio_read ( efab, 0, MII_LPA );
	gmii_lpa = ( falcon_mdio_read ( efab, 0, MII_STAT1000 ) >> 10 ) & 0x03;
	return ( ( gmii_lpa << 16 ) | mii_lpa );
}

/**
 * Calculate GMII autonegotiated link technology
 *
 */
static unsigned int
gmii_nway_result ( unsigned int negotiated )
{
	unsigned int other_bits;

	/* Mask out the speed and duplexity bits */
	other_bits = negotiated & LPA_OTHER;

	if ( negotiated & LPA_EF_1000FULL )
		return ( other_bits | LPA_EF_1000FULL );
	else if ( negotiated & LPA_EF_1000HALF )
		return ( other_bits | LPA_EF_1000HALF );
	else if ( negotiated & LPA_100FULL )
		return ( other_bits | LPA_100FULL );
	else if ( negotiated & LPA_100BASE4 )
		return ( other_bits | LPA_100BASE4 );
	else if ( negotiated & LPA_100HALF )
		return ( other_bits | LPA_100HALF );
	else if ( negotiated & LPA_10FULL )
		return ( other_bits | LPA_10FULL );
	else return ( other_bits | LPA_10HALF );
}

/**
 * Check GMII PHY link status
 *
 */
static int
gmii_link_ok ( struct efab_nic *efab )
{
	int status;
	int phy_status;

	/* BMSR is latching - it returns "link down" if the link has
	 * been down at any point since the last read.  To get a
	 * real-time status, we therefore read the register twice and
	 * use the result of the second read.
	 */
	(void) falcon_mdio_read ( efab, 0, MII_BMSR );
	status = falcon_mdio_read ( efab, 0, MII_BMSR );

	/* Read the PHY-specific Status Register.  This is
	 * non-latching, so we need do only a single read.
	 */
	phy_status = falcon_mdio_read ( efab, 0, GMII_PSSR );

	return ( ( status & BMSR_LSTATUS ) && ( phy_status & PSSR_LSTATUS ) );
}

/**************************************************************************
 *
 * MDIO routines
 *
 **************************************************************************
 */

/* Numbering of the MDIO Manageable Devices (MMDs) */
/* Physical Medium Attachment/ Physical Medium Dependent sublayer */
#define MDIO_MMD_PMAPMD	(1)
/* WAN Interface Sublayer */
#define MDIO_MMD_WIS	(2)
/* Physical Coding Sublayer */
#define MDIO_MMD_PCS	(3)
/* PHY Extender Sublayer */
#define MDIO_MMD_PHYXS	(4)
/* Extender Sublayer */
#define MDIO_MMD_DTEXS	(5)
/* Transmission convergence */
#define MDIO_MMD_TC	(6)
/* Auto negotiation */
#define MDIO_MMD_AN	(7)

/* Generic register locations */
#define MDIO_MMDREG_CTRL1	(0)
#define MDIO_MMDREG_STAT1	(1)
#define MDIO_MMDREG_DEVS0	(5)
#define MDIO_MMDREG_STAT2	(8)

/* Bits in MMDREG_CTRL1 */
/* Reset */
#define MDIO_MMDREG_CTRL1_RESET_LBN	(15)
#define MDIO_MMDREG_CTRL1_RESET_WIDTH	(1)

/* Bits in MMDREG_STAT1 */
#define MDIO_MMDREG_STAT1_FAULT_LBN	(7)
#define MDIO_MMDREG_STAT1_FAULT_WIDTH	(1)

/* Link state */
#define MDIO_MMDREG_STAT1_LINK_LBN	(2)
#define MDIO_MMDREG_STAT1_LINK_WIDTH	(1)

/* Bits in MMDREG_DEVS0. */
#define DEV_PRESENT_BIT(_b) (1 << _b)

#define MDIO_MMDREG_DEVS0_DTEXS	 DEV_PRESENT_BIT(MDIO_MMD_DTEXS)
#define MDIO_MMDREG_DEVS0_PHYXS	 DEV_PRESENT_BIT(MDIO_MMD_PHYXS)
#define MDIO_MMDREG_DEVS0_PCS	 DEV_PRESENT_BIT(MDIO_MMD_PCS)
#define MDIO_MMDREG_DEVS0_WIS	 DEV_PRESENT_BIT(MDIO_MMD_WIS)
#define MDIO_MMDREG_DEVS0_PMAPMD DEV_PRESENT_BIT(MDIO_MMD_PMAPMD)

#define MDIO_MMDREG_DEVS0_AN     DEV_PRESENT_BIT(MDIO_MMD_AN)

/* Bits in MMDREG_STAT2 */
#define MDIO_MMDREG_STAT2_PRESENT_VAL	(2)
#define MDIO_MMDREG_STAT2_PRESENT_LBN	(14)
#define MDIO_MMDREG_STAT2_PRESENT_WIDTH (2)

/* PHY XGXS lane state */
#define MDIO_PHYXS_LANE_STATE		(0x18) 
#define MDIO_PHYXS_LANE_ALIGNED_LBN	(12)
#define MDIO_PHYXS_LANE_SYNC0_LBN	(0)
#define MDIO_PHYXS_LANE_SYNC1_LBN	(1)
#define MDIO_PHYXS_LANE_SYNC2_LBN	(2)
#define MDIO_PHYXS_LANE_SYNC3_LBN	(3)

/* This ought to be ridiculous overkill. We expect it to fail rarely */
#define MDIO45_RESET_TRIES      100
#define MDIO45_RESET_SPINTIME   10

static int
mdio_clause45_wait_reset_mmds ( struct efab_nic* efab )
{
	int tries = MDIO45_RESET_TRIES;
	int in_reset;

	while(tries) {
		int mask = efab->phy_op->mmds;
		int mmd = 0;
		in_reset = 0;
		while(mask) {
			if (mask & 1) {
				int stat = falcon_mdio_read ( efab,  mmd,
							      MDIO_MMDREG_CTRL1 );
				if (stat < 0) {
					EFAB_ERR("Failed to read status of MMD %d\n",
						 mmd );
					in_reset = 1;
					break;
				}
				if (stat & (1 << MDIO_MMDREG_CTRL1_RESET_LBN))
					in_reset |= (1 << mmd);
			}
			mask = mask >> 1;
			mmd++;
		}
		if (!in_reset)
			break;
		tries--;
		mdelay ( MDIO45_RESET_SPINTIME );
	}
	if (in_reset != 0) {
		EFAB_ERR("Not all MMDs came out of reset in time. MMDs "
			 "still in reset: %x\n", in_reset);
		return -ETIMEDOUT;
	}
	return 0;
}

static int
mdio_clause45_reset_mmd ( struct efab_nic *efab, int mmd )
{
	int tries = MDIO45_RESET_TRIES;
	int ctrl;

	falcon_mdio_write ( efab, mmd, MDIO_MMDREG_CTRL1,
			    ( 1 << MDIO_MMDREG_CTRL1_RESET_LBN ) );

	/* Wait for the reset bit to clear. */
	do {
		mdelay ( MDIO45_RESET_SPINTIME );

		ctrl = falcon_mdio_read ( efab, mmd, MDIO_MMDREG_CTRL1 );
		if ( ~ctrl & ( 1 << MDIO_MMDREG_CTRL1_RESET_LBN ) )
			return 0;
	} while ( --tries );

	EFAB_ERR ( "Failed to reset mmd %d\n", mmd );

	return -ETIMEDOUT;
}

static int
mdio_clause45_links_ok(struct efab_nic *efab )
{
	int status, good;
	int ok = 1;
	int mmd = 0;
	int mmd_mask = efab->phy_op->mmds;

	while (mmd_mask) {
		if (mmd_mask & 1) {
			/* Double reads because link state is latched, and a
			 * read	moves the current state into the register */
			status = falcon_mdio_read ( efab, mmd,
						    MDIO_MMDREG_STAT1 );
			status = falcon_mdio_read ( efab, mmd,
						    MDIO_MMDREG_STAT1 );

			good = status & (1 << MDIO_MMDREG_STAT1_LINK_LBN);
			ok = ok && good;
		}
		mmd_mask = (mmd_mask >> 1);
		mmd++;
	}
	return ok;
}

static int
mdio_clause45_check_mmds ( struct efab_nic *efab )
{
	int mmd = 0;
	int devices = falcon_mdio_read ( efab, MDIO_MMD_PHYXS,
					 MDIO_MMDREG_DEVS0 );
	int mmd_mask = efab->phy_op->mmds;

	/* Check all the expected MMDs are present */
	if ( devices < 0 ) {
		EFAB_ERR ( "Failed to read devices present\n" );
		return -EIO;
	}
	if ( ( devices & mmd_mask ) != mmd_mask ) {
		EFAB_ERR ( "required MMDs not present: got %x, wanted %x\n",
			   devices, mmd_mask );
		return -EIO;
	}

	/* Check all required MMDs are responding and happy. */
	while ( mmd_mask ) {
		if ( mmd_mask & 1 ) {
			efab_dword_t reg;
			int status;
			reg.opaque = falcon_mdio_read ( efab, mmd,
							MDIO_MMDREG_STAT2 );
			status = EFAB_DWORD_FIELD ( reg,
						    MDIO_MMDREG_STAT2_PRESENT );
			if ( status != MDIO_MMDREG_STAT2_PRESENT_VAL ) {


				return -EIO;
			}
		}
		mmd_mask >>= 1;
		mmd++;
	}

	return 0;
}

/* I/O BAR address register */
#define FCN_IOM_IND_ADR_REG 0x0

/* I/O BAR data register */
#define FCN_IOM_IND_DAT_REG 0x4

/* Address region register */
#define FCN_ADR_REGION_REG_KER	0x00
#define FCN_ADR_REGION0_LBN	0
#define FCN_ADR_REGION0_WIDTH	18
#define FCN_ADR_REGION1_LBN	32
#define FCN_ADR_REGION1_WIDTH	18
#define FCN_ADR_REGION2_LBN	64
#define FCN_ADR_REGION2_WIDTH	18
#define FCN_ADR_REGION3_LBN	96
#define FCN_ADR_REGION3_WIDTH	18

/* Interrupt enable register */
#define FCN_INT_EN_REG_KER 0x0010
#define FCN_MEM_PERR_INT_EN_KER_LBN 5
#define FCN_MEM_PERR_INT_EN_KER_WIDTH 1
#define FCN_KER_INT_CHAR_LBN 4
#define FCN_KER_INT_CHAR_WIDTH 1
#define FCN_KER_INT_KER_LBN 3
#define FCN_KER_INT_KER_WIDTH 1
#define FCN_ILL_ADR_ERR_INT_EN_KER_LBN 2
#define FCN_ILL_ADR_ERR_INT_EN_KER_WIDTH 1
#define FCN_SRM_PERR_INT_EN_KER_LBN 1
#define FCN_SRM_PERR_INT_EN_KER_WIDTH 1
#define FCN_DRV_INT_EN_KER_LBN 0
#define FCN_DRV_INT_EN_KER_WIDTH 1

/* Interrupt status register */
#define FCN_INT_ADR_REG_KER	0x0030
#define FCN_INT_ADR_KER_LBN 0
#define FCN_INT_ADR_KER_WIDTH EFAB_DMA_TYPE_WIDTH ( 64 )

/* Interrupt status register (B0 only) */
#define INT_ISR0_B0 0x90
#define INT_ISR1_B0 0xA0

/* Interrupt acknowledge register (A0/A1 only) */
#define FCN_INT_ACK_KER_REG_A1 0x0050
#define INT_ACK_DUMMY_DATA_LBN 0
#define INT_ACK_DUMMY_DATA_WIDTH 32

/* Interrupt acknowledge work-around register (A0/A1 only )*/
#define WORK_AROUND_BROKEN_PCI_READS_REG_KER_A1 0x0070

/* Hardware initialisation register */
#define FCN_HW_INIT_REG_KER 0x00c0
#define FCN_BCSR_TARGET_MASK_LBN 101
#define FCN_BCSR_TARGET_MASK_WIDTH 4

/* SPI host command register */
#define FCN_EE_SPI_HCMD_REG 0x0100
#define FCN_EE_SPI_HCMD_CMD_EN_LBN 31
#define FCN_EE_SPI_HCMD_CMD_EN_WIDTH 1
#define FCN_EE_WR_TIMER_ACTIVE_LBN 28
#define FCN_EE_WR_TIMER_ACTIVE_WIDTH 1
#define FCN_EE_SPI_HCMD_SF_SEL_LBN 24
#define FCN_EE_SPI_HCMD_SF_SEL_WIDTH 1
#define FCN_EE_SPI_EEPROM 0
#define FCN_EE_SPI_FLASH 1
#define FCN_EE_SPI_HCMD_DABCNT_LBN 16
#define FCN_EE_SPI_HCMD_DABCNT_WIDTH 5
#define FCN_EE_SPI_HCMD_READ_LBN 15
#define FCN_EE_SPI_HCMD_READ_WIDTH 1
#define FCN_EE_SPI_READ 1
#define FCN_EE_SPI_WRITE 0
#define FCN_EE_SPI_HCMD_DUBCNT_LBN 12
#define FCN_EE_SPI_HCMD_DUBCNT_WIDTH 2
#define FCN_EE_SPI_HCMD_ADBCNT_LBN 8
#define FCN_EE_SPI_HCMD_ADBCNT_WIDTH 2
#define FCN_EE_SPI_HCMD_ENC_LBN 0
#define FCN_EE_SPI_HCMD_ENC_WIDTH 8

/* SPI host address register */
#define FCN_EE_SPI_HADR_REG 0x0110
#define FCN_EE_SPI_HADR_DUBYTE_LBN 24
#define FCN_EE_SPI_HADR_DUBYTE_WIDTH 8
#define FCN_EE_SPI_HADR_ADR_LBN 0
#define FCN_EE_SPI_HADR_ADR_WIDTH 24

/* SPI host data register */
#define FCN_EE_SPI_HDATA_REG 0x0120
#define FCN_EE_SPI_HDATA3_LBN 96
#define FCN_EE_SPI_HDATA3_WIDTH 32
#define FCN_EE_SPI_HDATA2_LBN 64
#define FCN_EE_SPI_HDATA2_WIDTH 32
#define FCN_EE_SPI_HDATA1_LBN 32
#define FCN_EE_SPI_HDATA1_WIDTH 32
#define FCN_EE_SPI_HDATA0_LBN 0
#define FCN_EE_SPI_HDATA0_WIDTH 32

/* VPD Config 0 Register register */
#define FCN_EE_VPD_CFG_REG 0x0140
#define FCN_EE_VPD_EN_LBN 0
#define FCN_EE_VPD_EN_WIDTH 1
#define FCN_EE_VPD_EN_AD9_MODE_LBN 1
#define FCN_EE_VPD_EN_AD9_MODE_WIDTH 1
#define FCN_EE_EE_CLOCK_DIV_LBN 112
#define FCN_EE_EE_CLOCK_DIV_WIDTH 7
#define FCN_EE_SF_CLOCK_DIV_LBN 120
#define FCN_EE_SF_CLOCK_DIV_WIDTH 7


/* NIC status register */
#define FCN_NIC_STAT_REG 0x0200
#define FCN_ONCHIP_SRAM_LBN 16
#define FCN_ONCHIP_SRAM_WIDTH 1
#define FCN_SF_PRST_LBN 9
#define FCN_SF_PRST_WIDTH 1
#define FCN_EE_PRST_LBN 8
#define FCN_EE_PRST_WIDTH 1
#define FCN_EE_STRAP_LBN 7
#define FCN_EE_STRAP_WIDTH 1
#define FCN_PCI_PCIX_MODE_LBN 4
#define FCN_PCI_PCIX_MODE_WIDTH 3
#define FCN_PCI_PCIX_MODE_PCI33_DECODE 0
#define FCN_PCI_PCIX_MODE_PCI66_DECODE 1
#define FCN_PCI_PCIX_MODE_PCIX66_DECODE 5
#define FCN_PCI_PCIX_MODE_PCIX100_DECODE 6
#define FCN_PCI_PCIX_MODE_PCIX133_DECODE 7
#define FCN_STRAP_ISCSI_EN_LBN 3
#define FCN_STRAP_ISCSI_EN_WIDTH 1
#define FCN_STRAP_PINS_LBN 0
#define FCN_STRAP_PINS_WIDTH 3
#define FCN_STRAP_10G_LBN 2
#define FCN_STRAP_10G_WIDTH 1
#define FCN_STRAP_DUAL_PORT_LBN 1
#define FCN_STRAP_DUAL_PORT_WIDTH 1
#define FCN_STRAP_PCIE_LBN 0
#define FCN_STRAP_PCIE_WIDTH 1

/* Falcon revisions */
#define FALCON_REV_A0 0
#define FALCON_REV_A1 1
#define FALCON_REV_B0 2

/* GPIO control register */
#define FCN_GPIO_CTL_REG_KER 0x0210
#define FCN_GPIO_CTL_REG_KER 0x0210

#define FCN_GPIO3_OEN_LBN 27
#define FCN_GPIO3_OEN_WIDTH 1
#define FCN_GPIO2_OEN_LBN 26
#define FCN_GPIO2_OEN_WIDTH 1
#define FCN_GPIO1_OEN_LBN 25
#define FCN_GPIO1_OEN_WIDTH 1
#define FCN_GPIO0_OEN_LBN 24
#define FCN_GPIO0_OEN_WIDTH 1

#define FCN_GPIO3_OUT_LBN 19
#define FCN_GPIO3_OUT_WIDTH 1
#define FCN_GPIO2_OUT_LBN 18
#define FCN_GPIO2_OUT_WIDTH 1
#define FCN_GPIO1_OUT_LBN 17
#define FCN_GPIO1_OUT_WIDTH 1
#define FCN_GPIO0_OUT_LBN 16
#define FCN_GPIO0_OUT_WIDTH 1

#define FCN_GPIO3_IN_LBN 11
#define FCN_GPIO3_IN_WIDTH 1
#define FCN_GPIO2_IN_LBN 10
#define FCN_GPIO2_IN_WIDTH 1
#define FCN_GPIO1_IN_LBN 9
#define FCN_GPIO1_IN_WIDTH 1
#define FCN_GPIO0_IN_LBN 8
#define FCN_GPIO0_IN_WIDTH 1

#define FCN_FLASH_PRESENT_LBN 7
#define FCN_FLASH_PRESENT_WIDTH 1
#define FCN_EEPROM_PRESENT_LBN 6
#define FCN_EEPROM_PRESENT_WIDTH 1
#define FCN_BOOTED_USING_NVDEVICE_LBN 3
#define FCN_BOOTED_USING_NVDEVICE_WIDTH 1

/* Defines for extra non-volatile storage */
#define FCN_NV_MAGIC_NUMBER 0xFA1C

/* Global control register */
#define FCN_GLB_CTL_REG_KER	0x0220
#define FCN_EXT_PHY_RST_CTL_LBN 63
#define FCN_EXT_PHY_RST_CTL_WIDTH 1
#define FCN_PCIE_SD_RST_CTL_LBN 61
#define FCN_PCIE_SD_RST_CTL_WIDTH 1
#define FCN_PCIE_STCK_RST_CTL_LBN 59
#define FCN_PCIE_STCK_RST_CTL_WIDTH 1
#define FCN_PCIE_NSTCK_RST_CTL_LBN 58
#define FCN_PCIE_NSTCK_RST_CTL_WIDTH 1
#define FCN_PCIE_CORE_RST_CTL_LBN 57
#define FCN_PCIE_CORE_RST_CTL_WIDTH 1
#define FCN_EE_RST_CTL_LBN 49
#define FCN_EE_RST_CTL_WIDTH 1
#define FCN_RST_EXT_PHY_LBN 31
#define FCN_RST_EXT_PHY_WIDTH 1
#define FCN_EXT_PHY_RST_DUR_LBN 1
#define FCN_EXT_PHY_RST_DUR_WIDTH 3
#define FCN_SWRST_LBN 0
#define FCN_SWRST_WIDTH 1
#define INCLUDE_IN_RESET 0
#define EXCLUDE_FROM_RESET 1

/* FPGA build version */
#define FCN_ALTERA_BUILD_REG_KER 0x0300
#define FCN_VER_MAJOR_LBN 24
#define FCN_VER_MAJOR_WIDTH 8
#define FCN_VER_MINOR_LBN 16
#define FCN_VER_MINOR_WIDTH 8
#define FCN_VER_BUILD_LBN 0
#define FCN_VER_BUILD_WIDTH 16
#define FCN_VER_ALL_LBN 0
#define FCN_VER_ALL_WIDTH 32

/* Spare EEPROM bits register (flash 0x390) */
#define FCN_SPARE_REG_KER 0x310
#define FCN_MEM_PERR_EN_TX_DATA_LBN 72
#define FCN_MEM_PERR_EN_TX_DATA_WIDTH 2

/* Timer table for kernel access */
#define FCN_TIMER_CMD_REG_KER 0x420
#define FCN_TIMER_MODE_LBN 12
#define FCN_TIMER_MODE_WIDTH 2
#define FCN_TIMER_MODE_DIS 0
#define FCN_TIMER_MODE_INT_HLDOFF 1
#define FCN_TIMER_VAL_LBN 0
#define FCN_TIMER_VAL_WIDTH 12

/* Receive configuration register */
#define FCN_RX_CFG_REG_KER 0x800
#define FCN_RX_XOFF_EN_LBN 0
#define FCN_RX_XOFF_EN_WIDTH 1

/* SRAM receive descriptor cache configuration register */
#define FCN_SRM_RX_DC_CFG_REG_KER 0x610
#define FCN_SRM_RX_DC_BASE_ADR_LBN 0
#define FCN_SRM_RX_DC_BASE_ADR_WIDTH 21

/* SRAM transmit descriptor cache configuration register */
#define FCN_SRM_TX_DC_CFG_REG_KER 0x620
#define FCN_SRM_TX_DC_BASE_ADR_LBN 0
#define FCN_SRM_TX_DC_BASE_ADR_WIDTH 21

/* SRAM configuration register */
#define FCN_SRM_CFG_REG_KER 0x630
#define FCN_SRAM_OOB_ADR_INTEN_LBN 5
#define FCN_SRAM_OOB_ADR_INTEN_WIDTH 1
#define FCN_SRAM_OOB_BUF_INTEN_LBN 4
#define FCN_SRAM_OOB_BUF_INTEN_WIDTH 1
#define FCN_SRAM_OOB_BT_INIT_EN_LBN 3
#define FCN_SRAM_OOB_BT_INIT_EN_WIDTH 1
#define FCN_SRM_NUM_BANK_LBN 2
#define FCN_SRM_NUM_BANK_WIDTH 1
#define FCN_SRM_BANK_SIZE_LBN 0
#define FCN_SRM_BANK_SIZE_WIDTH 2
#define FCN_SRM_NUM_BANKS_AND_BANK_SIZE_LBN 0
#define FCN_SRM_NUM_BANKS_AND_BANK_SIZE_WIDTH 3

#define FCN_RX_CFG_REG_KER 0x800
#define FCN_RX_INGR_EN_B0_LBN 47
#define FCN_RX_INGR_EN_B0_WIDTH 1
#define FCN_RX_USR_BUF_SIZE_B0_LBN 19
#define FCN_RX_USR_BUF_SIZE_B0_WIDTH 9
#define FCN_RX_XON_MAC_TH_B0_LBN 10
#define FCN_RX_XON_MAC_TH_B0_WIDTH 9
#define FCN_RX_XOFF_MAC_TH_B0_LBN 1
#define FCN_RX_XOFF_MAC_TH_B0_WIDTH 9
#define FCN_RX_XOFF_MAC_EN_B0_LBN 0
#define FCN_RX_XOFF_MAC_EN_B0_WIDTH 1
#define FCN_RX_USR_BUF_SIZE_A1_LBN 11
#define FCN_RX_USR_BUF_SIZE_A1_WIDTH 9
#define FCN_RX_XON_MAC_TH_A1_LBN 6
#define FCN_RX_XON_MAC_TH_A1_WIDTH 5
#define FCN_RX_XOFF_MAC_TH_A1_LBN 1
#define FCN_RX_XOFF_MAC_TH_A1_WIDTH 5
#define FCN_RX_XOFF_MAC_EN_A1_LBN 0
#define FCN_RX_XOFF_MAC_EN_A1_WIDTH 1

#define FCN_RX_USR_BUF_SIZE_A1_LBN 11
#define FCN_RX_USR_BUF_SIZE_A1_WIDTH 9
#define FCN_RX_XOFF_MAC_EN_A1_LBN 0
#define FCN_RX_XOFF_MAC_EN_A1_WIDTH 1

/* Receive filter control register */
#define FCN_RX_FILTER_CTL_REG_KER 0x810
#define FCN_UDP_FULL_SRCH_LIMIT_LBN 32
#define FCN_UDP_FULL_SRCH_LIMIT_WIDTH 8
#define FCN_NUM_KER_LBN 24
#define FCN_NUM_KER_WIDTH 2
#define FCN_UDP_WILD_SRCH_LIMIT_LBN 16
#define FCN_UDP_WILD_SRCH_LIMIT_WIDTH 8
#define FCN_TCP_WILD_SRCH_LIMIT_LBN 8
#define FCN_TCP_WILD_SRCH_LIMIT_WIDTH 8
#define FCN_TCP_FULL_SRCH_LIMIT_LBN 0
#define FCN_TCP_FULL_SRCH_LIMIT_WIDTH 8

/* RX queue flush register */
#define FCN_RX_FLUSH_DESCQ_REG_KER 0x0820
#define FCN_RX_FLUSH_DESCQ_CMD_LBN 24
#define FCN_RX_FLUSH_DESCQ_CMD_WIDTH 1
#define FCN_RX_FLUSH_DESCQ_LBN 0
#define FCN_RX_FLUSH_DESCQ_WIDTH 12

/* Receive descriptor update register */
#define FCN_RX_DESC_UPD_REG_KER 0x0830
#define FCN_RX_DESC_WPTR_LBN 96
#define FCN_RX_DESC_WPTR_WIDTH 12
#define FCN_RX_DESC_UPD_REG_KER_DWORD ( FCN_RX_DESC_UPD_REG_KER + 12 )
#define FCN_RX_DESC_WPTR_DWORD_LBN 0
#define FCN_RX_DESC_WPTR_DWORD_WIDTH 12

/* Receive descriptor cache configuration register */
#define FCN_RX_DC_CFG_REG_KER 0x840
#define FCN_RX_DC_SIZE_LBN 0
#define FCN_RX_DC_SIZE_WIDTH 2

#define FCN_RX_SELF_RST_REG_KER 0x890
#define FCN_RX_ISCSI_DIS_LBN 17
#define FCN_RX_ISCSI_DIS_WIDTH 1
#define FCN_RX_NODESC_WAIT_DIS_LBN 9
#define FCN_RX_NODESC_WAIT_DIS_WIDTH 1
#define FCN_RX_RECOVERY_EN_LBN 8
#define FCN_RX_RECOVERY_EN_WIDTH 1

/* TX queue flush register */
#define FCN_TX_FLUSH_DESCQ_REG_KER 0x0a00
#define FCN_TX_FLUSH_DESCQ_CMD_LBN 12
#define FCN_TX_FLUSH_DESCQ_CMD_WIDTH 1
#define FCN_TX_FLUSH_DESCQ_LBN 0
#define FCN_TX_FLUSH_DESCQ_WIDTH 12

/* Transmit configuration register 2 */
#define FCN_TX_CFG2_REG_KER 0xa80
#define FCN_TX_DIS_NON_IP_EV_LBN 17
#define FCN_TX_DIS_NON_IP_EV_WIDTH 1

/* Transmit descriptor update register */
#define FCN_TX_DESC_UPD_REG_KER 0x0a10
#define FCN_TX_DESC_WPTR_LBN 96
#define FCN_TX_DESC_WPTR_WIDTH 12
#define FCN_TX_DESC_UPD_REG_KER_DWORD ( FCN_TX_DESC_UPD_REG_KER + 12 )
#define FCN_TX_DESC_WPTR_DWORD_LBN 0
#define FCN_TX_DESC_WPTR_DWORD_WIDTH 12

/* Transmit descriptor cache configuration register */
#define FCN_TX_DC_CFG_REG_KER 0xa20
#define FCN_TX_DC_SIZE_LBN 0
#define FCN_TX_DC_SIZE_WIDTH 2

/* PHY management transmit data register */
#define FCN_MD_TXD_REG_KER 0xc00
#define FCN_MD_TXD_LBN 0
#define FCN_MD_TXD_WIDTH 16

/* PHY management receive data register */
#define FCN_MD_RXD_REG_KER 0xc10
#define FCN_MD_RXD_LBN 0
#define FCN_MD_RXD_WIDTH 16

/* PHY management configuration & status register */
#define FCN_MD_CS_REG_KER 0xc20
#define FCN_MD_GC_LBN 4
#define FCN_MD_GC_WIDTH 1
#define FCN_MD_RIC_LBN 2
#define FCN_MD_RIC_WIDTH 1
#define FCN_MD_RDC_LBN 1
#define FCN_MD_RDC_WIDTH 1
#define FCN_MD_WRC_LBN 0
#define FCN_MD_WRC_WIDTH 1

/* PHY management PHY address register */
#define FCN_MD_PHY_ADR_REG_KER 0xc30
#define FCN_MD_PHY_ADR_LBN 0
#define FCN_MD_PHY_ADR_WIDTH 16

/* PHY management ID register */
#define FCN_MD_ID_REG_KER 0xc40
#define FCN_MD_PRT_ADR_LBN 11
#define FCN_MD_PRT_ADR_WIDTH 5
#define FCN_MD_DEV_ADR_LBN 6
#define FCN_MD_DEV_ADR_WIDTH 5

/* PHY management status & mask register */
#define FCN_MD_STAT_REG_KER 0xc50
#define FCN_MD_PINT_LBN 4
#define FCN_MD_PINT_WIDTH 1
#define FCN_MD_DONE_LBN 3
#define FCN_MD_DONE_WIDTH 1
#define FCN_MD_BSERR_LBN 2
#define FCN_MD_BSERR_WIDTH 1
#define FCN_MD_LNFL_LBN 1
#define FCN_MD_LNFL_WIDTH 1
#define FCN_MD_BSY_LBN 0
#define FCN_MD_BSY_WIDTH 1

/* Port 0 and 1 MAC control registers */
#define FCN_MAC0_CTRL_REG_KER 0xc80
#define FCN_MAC1_CTRL_REG_KER 0xc90
#define FCN_MAC_XOFF_VAL_LBN 16
#define FCN_MAC_XOFF_VAL_WIDTH 16
#define FCN_MAC_BCAD_ACPT_LBN 4
#define FCN_MAC_BCAD_ACPT_WIDTH 1
#define FCN_MAC_UC_PROM_LBN 3
#define FCN_MAC_UC_PROM_WIDTH 1
#define FCN_MAC_LINK_STATUS_LBN 2
#define FCN_MAC_LINK_STATUS_WIDTH 1
#define FCN_MAC_SPEED_LBN 0
#define FCN_MAC_SPEED_WIDTH 2

/* 10Gig Xaui XGXS Default Values  */
#define XX_TXDRV_DEQ_DEFAULT 0xe /* deq=.6 */
#define XX_TXDRV_DTX_DEFAULT 0x5 /* 1.25 */
#define XX_SD_CTL_DRV_DEFAULT 0  /* 20mA */

/* GMAC registers */
#define FALCON_GMAC_REGBANK 0xe00
#define FALCON_GMAC_REGBANK_SIZE 0x200
#define FALCON_GMAC_REG_SIZE 0x10

/* XGMAC registers */
#define FALCON_XMAC_REGBANK 0x1200
#define FALCON_XMAC_REGBANK_SIZE 0x200
#define FALCON_XMAC_REG_SIZE 0x10

/* XGMAC address register low */
#define FCN_XM_ADR_LO_REG_MAC 0x00
#define FCN_XM_ADR_3_LBN 24
#define FCN_XM_ADR_3_WIDTH 8
#define FCN_XM_ADR_2_LBN 16
#define FCN_XM_ADR_2_WIDTH 8
#define FCN_XM_ADR_1_LBN 8
#define FCN_XM_ADR_1_WIDTH 8
#define FCN_XM_ADR_0_LBN 0
#define FCN_XM_ADR_0_WIDTH 8

/* XGMAC address register high */
#define FCN_XM_ADR_HI_REG_MAC 0x01
#define FCN_XM_ADR_5_LBN 8
#define FCN_XM_ADR_5_WIDTH 8
#define FCN_XM_ADR_4_LBN 0
#define FCN_XM_ADR_4_WIDTH 8

/* XGMAC global configuration - port 0*/
#define FCN_XM_GLB_CFG_REG_MAC 0x02
#define FCN_XM_RX_STAT_EN_LBN 11
#define FCN_XM_RX_STAT_EN_WIDTH 1
#define FCN_XM_TX_STAT_EN_LBN 10
#define FCN_XM_TX_STAT_EN_WIDTH 1
#define FCN_XM_RX_JUMBO_MODE_LBN 6
#define FCN_XM_RX_JUMBO_MODE_WIDTH 1
#define FCN_XM_CORE_RST_LBN 0
#define FCN_XM_CORE_RST_WIDTH 1

/* XGMAC transmit configuration - port 0 */
#define FCN_XM_TX_CFG_REG_MAC 0x03
#define FCN_XM_IPG_LBN 16
#define FCN_XM_IPG_WIDTH 4
#define FCN_XM_FCNTL_LBN 10
#define FCN_XM_FCNTL_WIDTH 1
#define FCN_XM_TXCRC_LBN 8
#define FCN_XM_TXCRC_WIDTH 1
#define FCN_XM_AUTO_PAD_LBN 5
#define FCN_XM_AUTO_PAD_WIDTH 1
#define FCN_XM_TX_PRMBL_LBN 2
#define FCN_XM_TX_PRMBL_WIDTH 1
#define FCN_XM_TXEN_LBN 1
#define FCN_XM_TXEN_WIDTH 1

/* XGMAC receive configuration - port 0 */
#define FCN_XM_RX_CFG_REG_MAC 0x04
#define FCN_XM_PASS_CRC_ERR_LBN 25
#define FCN_XM_PASS_CRC_ERR_WIDTH 1
#define FCN_XM_AUTO_DEPAD_LBN 8
#define FCN_XM_AUTO_DEPAD_WIDTH 1
#define FCN_XM_RXEN_LBN 1
#define FCN_XM_RXEN_WIDTH 1

/* XGMAC management interrupt mask register */
#define FCN_XM_MGT_INT_MSK_REG_MAC_B0 0x5
#define FCN_XM_MSK_PRMBLE_ERR_LBN 2
#define FCN_XM_MSK_PRMBLE_ERR_WIDTH 1
#define FCN_XM_MSK_RMTFLT_LBN 1
#define FCN_XM_MSK_RMTFLT_WIDTH 1
#define FCN_XM_MSK_LCLFLT_LBN 0
#define FCN_XM_MSK_LCLFLT_WIDTH 1

/* XGMAC flow control register */
#define FCN_XM_FC_REG_MAC 0x7
#define FCN_XM_PAUSE_TIME_LBN 16
#define FCN_XM_PAUSE_TIME_WIDTH 16
#define FCN_XM_DIS_FCNTL_LBN 0
#define FCN_XM_DIS_FCNTL_WIDTH 1

/* XGMAC transmit parameter register */
#define FCN_XM_TX_PARAM_REG_MAC 0x0d
#define FCN_XM_TX_JUMBO_MODE_LBN 31
#define FCN_XM_TX_JUMBO_MODE_WIDTH 1
#define FCN_XM_MAX_TX_FRM_SIZE_LBN 16
#define FCN_XM_MAX_TX_FRM_SIZE_WIDTH 14
#define FCN_XM_ACPT_ALL_MCAST_LBN 11
#define FCN_XM_ACPT_ALL_MCAST_WIDTH 1

/* XGMAC receive parameter register */
#define FCN_XM_RX_PARAM_REG_MAC 0x0e
#define FCN_XM_MAX_RX_FRM_SIZE_LBN 0
#define FCN_XM_MAX_RX_FRM_SIZE_WIDTH 14

/* XGMAC management interrupt status register */
#define FCN_XM_MGT_INT_REG_MAC_B0 0x0f
#define FCN_XM_PRMBLE_ERR 2
#define FCN_XM_PRMBLE_WIDTH 1
#define FCN_XM_RMTFLT_LBN 1
#define FCN_XM_RMTFLT_WIDTH 1
#define FCN_XM_LCLFLT_LBN 0
#define FCN_XM_LCLFLT_WIDTH 1

/* XAUI XGXS core status register */
#define FCN_XX_ALIGN_DONE_LBN 20
#define FCN_XX_ALIGN_DONE_WIDTH 1
#define FCN_XX_CORE_STAT_REG_MAC 0x16
#define FCN_XX_SYNC_STAT_LBN 16
#define FCN_XX_SYNC_STAT_WIDTH 4
#define FCN_XX_SYNC_STAT_DECODE_SYNCED 0xf
#define FCN_XX_COMMA_DET_LBN 12
#define FCN_XX_COMMA_DET_WIDTH 4
#define FCN_XX_COMMA_DET_RESET 0xf
#define FCN_XX_CHARERR_LBN 4
#define FCN_XX_CHARERR_WIDTH 4
#define FCN_XX_CHARERR_RESET 0xf
#define FCN_XX_DISPERR_LBN 0
#define FCN_XX_DISPERR_WIDTH 4
#define FCN_XX_DISPERR_RESET 0xf

/* XGXS/XAUI powerdown/reset register */
#define FCN_XX_PWR_RST_REG_MAC 0x10
#define FCN_XX_PWRDND_EN_LBN 15
#define FCN_XX_PWRDND_EN_WIDTH 1
#define FCN_XX_PWRDNC_EN_LBN 14
#define FCN_XX_PWRDNC_EN_WIDTH 1
#define FCN_XX_PWRDNB_EN_LBN 13
#define FCN_XX_PWRDNB_EN_WIDTH 1
#define FCN_XX_PWRDNA_EN_LBN 12
#define FCN_XX_PWRDNA_EN_WIDTH 1
#define FCN_XX_RSTPLLCD_EN_LBN 9
#define FCN_XX_RSTPLLCD_EN_WIDTH 1
#define FCN_XX_RSTPLLAB_EN_LBN 8
#define FCN_XX_RSTPLLAB_EN_WIDTH 1
#define FCN_XX_RESETD_EN_LBN 7
#define FCN_XX_RESETD_EN_WIDTH 1
#define FCN_XX_RESETC_EN_LBN 6
#define FCN_XX_RESETC_EN_WIDTH 1
#define FCN_XX_RESETB_EN_LBN 5
#define FCN_XX_RESETB_EN_WIDTH 1
#define FCN_XX_RESETA_EN_LBN 4
#define FCN_XX_RESETA_EN_WIDTH 1
#define FCN_XX_RSTXGXSRX_EN_LBN 2
#define FCN_XX_RSTXGXSRX_EN_WIDTH 1
#define FCN_XX_RSTXGXSTX_EN_LBN 1
#define FCN_XX_RSTXGXSTX_EN_WIDTH 1
#define FCN_XX_RST_XX_EN_LBN 0
#define FCN_XX_RST_XX_EN_WIDTH 1


/* XGXS/XAUI powerdown/reset control register */
#define FCN_XX_SD_CTL_REG_MAC 0x11
#define FCN_XX_TERMADJ1_LBN 17
#define FCN_XX_TERMADJ1_WIDTH 1
#define FCN_XX_TERMADJ0_LBN 16
#define FCN_XX_TERMADJ0_WIDTH 1
#define FCN_XX_HIDRVD_LBN 15
#define FCN_XX_HIDRVD_WIDTH 1
#define FCN_XX_LODRVD_LBN 14
#define FCN_XX_LODRVD_WIDTH 1
#define FCN_XX_HIDRVC_LBN 13
#define FCN_XX_HIDRVC_WIDTH 1
#define FCN_XX_LODRVC_LBN 12
#define FCN_XX_LODRVC_WIDTH 1
#define FCN_XX_HIDRVB_LBN 11
#define FCN_XX_HIDRVB_WIDTH 1
#define FCN_XX_LODRVB_LBN 10
#define FCN_XX_LODRVB_WIDTH 1
#define FCN_XX_HIDRVA_LBN 9
#define FCN_XX_HIDRVA_WIDTH 1
#define FCN_XX_LODRVA_LBN 8
#define FCN_XX_LODRVA_WIDTH 1
#define FCN_XX_LPBKD_LBN 3
#define FCN_XX_LPBKD_WIDTH 1
#define FCN_XX_LPBKC_LBN 2
#define FCN_XX_LPBKC_WIDTH 1
#define FCN_XX_LPBKB_LBN 1
#define FCN_XX_LPBKB_WIDTH 1
#define FCN_XX_LPBKA_LBN 0
#define FCN_XX_LPBKA_WIDTH 1

#define FCN_XX_TXDRV_CTL_REG_MAC 0x12
#define FCN_XX_DEQD_LBN 28
#define FCN_XX_DEQD_WIDTH 4
#define FCN_XX_DEQC_LBN 24
#define FCN_XX_DEQC_WIDTH 4
#define FCN_XX_DEQB_LBN 20
#define FCN_XX_DEQB_WIDTH 4
#define FCN_XX_DEQA_LBN 16
#define FCN_XX_DEQA_WIDTH 4
#define FCN_XX_DTXD_LBN 12
#define FCN_XX_DTXD_WIDTH 4
#define FCN_XX_DTXC_LBN 8
#define FCN_XX_DTXC_WIDTH 4
#define FCN_XX_DTXB_LBN 4
#define FCN_XX_DTXB_WIDTH 4
#define FCN_XX_DTXA_LBN 0
#define FCN_XX_DTXA_WIDTH 4

/* Receive filter table */
#define FCN_RX_FILTER_TBL0 0xF00000 

/* Receive descriptor pointer table */
#define FCN_RX_DESC_PTR_TBL_KER_A1 0x11800
#define FCN_RX_DESC_PTR_TBL_KER_B0 0xF40000
#define FCN_RX_ISCSI_DDIG_EN_LBN 88
#define FCN_RX_ISCSI_DDIG_EN_WIDTH 1
#define FCN_RX_ISCSI_HDIG_EN_LBN 87
#define FCN_RX_ISCSI_HDIG_EN_WIDTH 1
#define FCN_RX_DESCQ_BUF_BASE_ID_LBN 36
#define FCN_RX_DESCQ_BUF_BASE_ID_WIDTH 20
#define FCN_RX_DESCQ_EVQ_ID_LBN 24
#define FCN_RX_DESCQ_EVQ_ID_WIDTH 12
#define FCN_RX_DESCQ_OWNER_ID_LBN 10
#define FCN_RX_DESCQ_OWNER_ID_WIDTH 14
#define FCN_RX_DESCQ_SIZE_LBN 3
#define FCN_RX_DESCQ_SIZE_WIDTH 2
#define FCN_RX_DESCQ_SIZE_4K 3
#define FCN_RX_DESCQ_SIZE_2K 2
#define FCN_RX_DESCQ_SIZE_1K 1
#define FCN_RX_DESCQ_SIZE_512 0
#define FCN_RX_DESCQ_TYPE_LBN 2
#define FCN_RX_DESCQ_TYPE_WIDTH 1
#define FCN_RX_DESCQ_JUMBO_LBN 1
#define FCN_RX_DESCQ_JUMBO_WIDTH 1
#define FCN_RX_DESCQ_EN_LBN 0
#define FCN_RX_DESCQ_EN_WIDTH 1

/* Transmit descriptor pointer table */
#define FCN_TX_DESC_PTR_TBL_KER_A1 0x11900
#define FCN_TX_DESC_PTR_TBL_KER_B0 0xF50000
#define FCN_TX_NON_IP_DROP_DIS_B0_LBN 91
#define FCN_TX_NON_IP_DROP_DIS_B0_WIDTH 1
#define FCN_TX_DESCQ_EN_LBN 88
#define FCN_TX_DESCQ_EN_WIDTH 1
#define FCN_TX_ISCSI_DDIG_EN_LBN 87
#define FCN_TX_ISCSI_DDIG_EN_WIDTH 1
#define FCN_TX_ISCSI_HDIG_EN_LBN 86
#define FCN_TX_ISCSI_HDIG_EN_WIDTH 1
#define FCN_TX_DESCQ_BUF_BASE_ID_LBN 36
#define FCN_TX_DESCQ_BUF_BASE_ID_WIDTH 20
#define FCN_TX_DESCQ_EVQ_ID_LBN 24
#define FCN_TX_DESCQ_EVQ_ID_WIDTH 12
#define FCN_TX_DESCQ_OWNER_ID_LBN 10
#define FCN_TX_DESCQ_OWNER_ID_WIDTH 14
#define FCN_TX_DESCQ_SIZE_LBN 3
#define FCN_TX_DESCQ_SIZE_WIDTH 2
#define FCN_TX_DESCQ_SIZE_4K 3
#define FCN_TX_DESCQ_SIZE_2K 2
#define FCN_TX_DESCQ_SIZE_1K 1
#define FCN_TX_DESCQ_SIZE_512 0
#define FCN_TX_DESCQ_TYPE_LBN 1
#define FCN_TX_DESCQ_TYPE_WIDTH 2
#define FCN_TX_DESCQ_FLUSH_LBN 0
#define FCN_TX_DESCQ_FLUSH_WIDTH 1

/* Event queue pointer */
#define FCN_EVQ_PTR_TBL_KER_A1 0x11a00
#define FCN_EVQ_PTR_TBL_KER_B0 0xf60000
#define FCN_EVQ_EN_LBN 23
#define FCN_EVQ_EN_WIDTH 1
#define FCN_EVQ_SIZE_LBN 20
#define FCN_EVQ_SIZE_WIDTH 3
#define FCN_EVQ_SIZE_32K 6
#define FCN_EVQ_SIZE_16K 5
#define FCN_EVQ_SIZE_8K 4
#define FCN_EVQ_SIZE_4K 3
#define FCN_EVQ_SIZE_2K 2
#define FCN_EVQ_SIZE_1K 1
#define FCN_EVQ_SIZE_512 0
#define FCN_EVQ_BUF_BASE_ID_LBN 0
#define FCN_EVQ_BUF_BASE_ID_WIDTH 20

/* RSS indirection table */
#define FCN_RX_RSS_INDIR_TBL_B0 0xFB0000

/* Event queue read pointer */
#define FCN_EVQ_RPTR_REG_KER_A1 0x11b00
#define FCN_EVQ_RPTR_REG_KER_B0 0xfa0000
#define FCN_EVQ_RPTR_LBN 0
#define FCN_EVQ_RPTR_WIDTH 14
#define FCN_EVQ_RPTR_REG_KER_DWORD_A1 ( FCN_EVQ_RPTR_REG_KER_A1 + 0 )
#define FCN_EVQ_RPTR_REG_KER_DWORD_B0 ( FCN_EVQ_RPTR_REG_KER_B0 + 0 )
#define FCN_EVQ_RPTR_DWORD_LBN 0
#define FCN_EVQ_RPTR_DWORD_WIDTH 14

/* Special buffer descriptors */
#define FCN_BUF_FULL_TBL_KER_A1 0x18000
#define FCN_BUF_FULL_TBL_KER_B0 0x800000
#define FCN_IP_DAT_BUF_SIZE_LBN 50
#define FCN_IP_DAT_BUF_SIZE_WIDTH 1
#define FCN_IP_DAT_BUF_SIZE_8K 1
#define FCN_IP_DAT_BUF_SIZE_4K 0
#define FCN_BUF_ADR_FBUF_LBN 14
#define FCN_BUF_ADR_FBUF_WIDTH 34
#define FCN_BUF_OWNER_ID_FBUF_LBN 0
#define FCN_BUF_OWNER_ID_FBUF_WIDTH 14

/** Offset of a GMAC register within Falcon */
#define FALCON_GMAC_REG( efab, mac_reg )				\
	( FALCON_GMAC_REGBANK +					\
	  ( (mac_reg) * FALCON_GMAC_REG_SIZE ) )

/** Offset of an XMAC register within Falcon */
#define FALCON_XMAC_REG( efab_port, mac_reg )			\
	( FALCON_XMAC_REGBANK +					\
	  ( (mac_reg) * FALCON_XMAC_REG_SIZE ) )

#define FCN_MAC_DATA_LBN 0
#define FCN_MAC_DATA_WIDTH 32

/* Transmit descriptor */
#define FCN_TX_KER_PORT_LBN 63
#define FCN_TX_KER_PORT_WIDTH 1
#define FCN_TX_KER_BYTE_CNT_LBN 48
#define FCN_TX_KER_BYTE_CNT_WIDTH 14
#define FCN_TX_KER_BUF_ADR_LBN 0
#define FCN_TX_KER_BUF_ADR_WIDTH EFAB_DMA_TYPE_WIDTH ( 46 )


/* Receive descriptor */
#define FCN_RX_KER_BUF_SIZE_LBN 48
#define FCN_RX_KER_BUF_SIZE_WIDTH 14
#define FCN_RX_KER_BUF_ADR_LBN 0
#define FCN_RX_KER_BUF_ADR_WIDTH EFAB_DMA_TYPE_WIDTH ( 46 )

/* Event queue entries */
#define FCN_EV_CODE_LBN 60
#define FCN_EV_CODE_WIDTH 4
#define FCN_RX_IP_EV_DECODE 0
#define FCN_TX_IP_EV_DECODE 2
#define FCN_DRIVER_EV_DECODE 5

/* Receive events */
#define FCN_RX_EV_PKT_OK_LBN 56
#define FCN_RX_EV_PKT_OK_WIDTH 1
#define FCN_RX_PORT_LBN 30
#define FCN_RX_PORT_WIDTH 1
#define FCN_RX_EV_BYTE_CNT_LBN 16
#define FCN_RX_EV_BYTE_CNT_WIDTH 14
#define FCN_RX_EV_DESC_PTR_LBN 0
#define FCN_RX_EV_DESC_PTR_WIDTH 12

/* Transmit events */
#define FCN_TX_EV_DESC_PTR_LBN 0
#define FCN_TX_EV_DESC_PTR_WIDTH 12

/*******************************************************************************
 *
 *
 * Low-level hardware access
 *
 *
 *******************************************************************************/ 

#define FCN_REVISION_REG(efab, reg) \
	( ( efab->pci_revision == FALCON_REV_B0 ) ? reg ## _B0 : reg ## _A1 )

#define EFAB_SET_OWORD_FIELD_VER(efab, reg, field, val)			\
	if ( efab->pci_revision == FALCON_REV_B0 )			\
		EFAB_SET_OWORD_FIELD ( reg, field ## _B0, val );	\
	else								\
		EFAB_SET_OWORD_FIELD ( reg, field ## _A1, val );

#if FALCON_USE_IO_BAR

/* Write dword via the I/O BAR */
static inline void _falcon_writel ( struct efab_nic *efab, uint32_t value,
				    unsigned int reg ) {
	outl ( reg, efab->iobase + FCN_IOM_IND_ADR_REG );
	outl ( value, efab->iobase + FCN_IOM_IND_DAT_REG );
}

/* Read dword via the I/O BAR */
static inline uint32_t _falcon_readl ( struct efab_nic *efab,
				       unsigned int reg ) {
	outl ( reg, efab->iobase + FCN_IOM_IND_ADR_REG );
	return inl ( efab->iobase + FCN_IOM_IND_DAT_REG );
}

#else /* FALCON_USE_IO_BAR */

#define _falcon_writel( efab, value, reg ) \
	writel ( (value), (efab)->membase + (reg) )
#define _falcon_readl( efab, reg ) readl ( (efab)->membase + (reg) )

#endif /* FALCON_USE_IO_BAR */

/**
 * Write to a Falcon register
 *
 */
static inline void
falcon_write ( struct efab_nic *efab, efab_oword_t *value, unsigned int reg )
{

	EFAB_REGDUMP ( "Writing register %x with " EFAB_OWORD_FMT "\n",
		       reg, EFAB_OWORD_VAL ( *value ) );

	_falcon_writel ( efab, value->u32[0], reg + 0  );
	_falcon_writel ( efab, value->u32[1], reg + 4  );
	_falcon_writel ( efab, value->u32[2], reg + 8  );
	wmb();
	_falcon_writel ( efab, value->u32[3], reg + 12 );
	wmb();
}

/**
 * Write to Falcon SRAM
 *
 */
static inline void
falcon_write_sram ( struct efab_nic *efab, efab_qword_t *value,
		    unsigned int index )
{
	unsigned int reg = ( FCN_REVISION_REG ( efab, FCN_BUF_FULL_TBL_KER ) +
			     ( index * sizeof ( *value ) ) );

	EFAB_REGDUMP ( "Writing SRAM register %x with " EFAB_QWORD_FMT "\n",
		       reg, EFAB_QWORD_VAL ( *value ) );

	_falcon_writel ( efab, value->u32[0], reg + 0  );
	_falcon_writel ( efab, value->u32[1], reg + 4  );
	wmb();
}

/**
 * Write dword to Falcon register that allows partial writes
 *
 */
static inline void
falcon_writel ( struct efab_nic *efab, efab_dword_t *value, unsigned int reg )
{
	EFAB_REGDUMP ( "Writing partial register %x with " EFAB_DWORD_FMT "\n",
		       reg, EFAB_DWORD_VAL ( *value ) );
	_falcon_writel ( efab, value->u32[0], reg );
}

/**
 * Read from a Falcon register
 *
 */
static inline void
falcon_read ( struct efab_nic *efab, efab_oword_t *value, unsigned int reg )
{
	value->u32[0] = _falcon_readl ( efab, reg + 0  );
	wmb();
	value->u32[1] = _falcon_readl ( efab, reg + 4  );
	value->u32[2] = _falcon_readl ( efab, reg + 8  );
	value->u32[3] = _falcon_readl ( efab, reg + 12 );

	EFAB_REGDUMP ( "Read from register %x, got " EFAB_OWORD_FMT "\n",
		       reg, EFAB_OWORD_VAL ( *value ) );
}

/** 
 * Read from Falcon SRAM
 *
 */
static inline void
falcon_read_sram ( struct efab_nic *efab, efab_qword_t *value,
		   unsigned int index )
{
	unsigned int reg = ( FCN_REVISION_REG ( efab, FCN_BUF_FULL_TBL_KER ) +
			     ( index * sizeof ( *value ) ) );

	value->u32[0] = _falcon_readl ( efab, reg + 0 );
	value->u32[1] = _falcon_readl ( efab, reg + 4 );
	EFAB_REGDUMP ( "Read from SRAM register %x, got " EFAB_QWORD_FMT "\n",
		       reg, EFAB_QWORD_VAL ( *value ) );
}

/**
 * Read dword from a portion of a Falcon register
 *
 */
static inline void
falcon_readl ( struct efab_nic *efab, efab_dword_t *value, unsigned int reg )
{
	value->u32[0] = _falcon_readl ( efab, reg );
	EFAB_REGDUMP ( "Read from register %x, got " EFAB_DWORD_FMT "\n",
		       reg, EFAB_DWORD_VAL ( *value ) );
}

#define FCN_DUMP_REG( efab, _reg ) do {				\
		efab_oword_t reg;				\
		falcon_read ( efab, &reg, _reg );		\
		EFAB_LOG ( #_reg " = " EFAB_OWORD_FMT "\n",	\
			   EFAB_OWORD_VAL ( reg ) );		\
	} while ( 0 );

#define FCN_DUMP_MAC_REG( efab, _mac_reg ) do {				\
		efab_dword_t reg;					\
		efab->mac_op->mac_readl ( efab, &reg, _mac_reg );	\
		EFAB_LOG ( #_mac_reg " = " EFAB_DWORD_FMT "\n",		\
			   EFAB_DWORD_VAL ( reg ) );			\
	} while ( 0 );

/**
 * See if an event is present
 *
 * @v event		Falcon event structure
 * @ret True		An event is pending
 * @ret False		No event is pending
 *
 * We check both the high and low dword of the event for all ones.  We
 * wrote all ones when we cleared the event, and no valid event can
 * have all ones in either its high or low dwords.  This approach is
 * robust against reordering.
 *
 * Note that using a single 64-bit comparison is incorrect; even
 * though the CPU read will be atomic, the DMA write may not be.
 */
static inline int
falcon_event_present ( falcon_event_t* event )
{
	return ( ! ( EFAB_DWORD_IS_ALL_ONES ( event->dword[0] ) |
		     EFAB_DWORD_IS_ALL_ONES ( event->dword[1] ) ) );
}

static void
falcon_eventq_read_ack ( struct efab_nic *efab, struct efab_ev_queue *ev_queue )
{
	efab_dword_t reg;

	EFAB_POPULATE_DWORD_1 ( reg, FCN_EVQ_RPTR_DWORD, ev_queue->read_ptr );
	falcon_writel ( efab, &reg,
			FCN_REVISION_REG ( efab, FCN_EVQ_RPTR_REG_KER_DWORD ) );
}

#if 0
/**
 * Dump register contents (for debugging)
 *
 * Marked as static inline so that it will not be compiled in if not
 * used.
 */
static inline void
falcon_dump_regs ( struct efab_nic *efab )
{
	FCN_DUMP_REG ( efab, FCN_INT_EN_REG_KER );
	FCN_DUMP_REG ( efab, FCN_INT_ADR_REG_KER );
	FCN_DUMP_REG ( efab, FCN_GLB_CTL_REG_KER );
	FCN_DUMP_REG ( efab, FCN_TIMER_CMD_REG_KER );
	FCN_DUMP_REG ( efab, FCN_SRM_RX_DC_CFG_REG_KER );
	FCN_DUMP_REG ( efab, FCN_SRM_TX_DC_CFG_REG_KER );
	FCN_DUMP_REG ( efab, FCN_RX_FILTER_CTL_REG_KER );
	FCN_DUMP_REG ( efab, FCN_RX_DC_CFG_REG_KER );
	FCN_DUMP_REG ( efab, FCN_TX_DC_CFG_REG_KER );
	FCN_DUMP_REG ( efab, FCN_MAC0_CTRL_REG_KER );
	FCN_DUMP_REG ( efab, FCN_MAC1_CTRL_REG_KER );
	FCN_DUMP_REG ( efab, FCN_REVISION_REG ( efab, FCN_RX_DESC_PTR_TBL_KER ) );
	FCN_DUMP_REG ( efab, FCN_REVISION_REG ( efab, FCN_TX_DESC_PTR_TBL_KER ) );
	FCN_DUMP_REG ( efab, FCN_REVISION_REG ( efab, FCN_EVQ_PTR_TBL_KER ) );
	FCN_DUMP_MAC_REG ( efab, GM_CFG1_REG_MAC );
	FCN_DUMP_MAC_REG ( efab, GM_CFG2_REG_MAC );
	FCN_DUMP_MAC_REG ( efab, GM_MAX_FLEN_REG_MAC );
	FCN_DUMP_MAC_REG ( efab, GM_MII_MGMT_CFG_REG_MAC );
	FCN_DUMP_MAC_REG ( efab, GM_ADR1_REG_MAC );
	FCN_DUMP_MAC_REG ( efab, GM_ADR2_REG_MAC );
	FCN_DUMP_MAC_REG ( efab, GMF_CFG0_REG_MAC );
	FCN_DUMP_MAC_REG ( efab, GMF_CFG1_REG_MAC );
	FCN_DUMP_MAC_REG ( efab, GMF_CFG2_REG_MAC );
	FCN_DUMP_MAC_REG ( efab, GMF_CFG3_REG_MAC );
	FCN_DUMP_MAC_REG ( efab, GMF_CFG4_REG_MAC );
	FCN_DUMP_MAC_REG ( efab, GMF_CFG5_REG_MAC );
}
#endif

static void
falcon_interrupts ( struct efab_nic *efab, int enabled, int force )
{
	efab_oword_t int_en_reg_ker;

	EFAB_POPULATE_OWORD_2 ( int_en_reg_ker,
				FCN_KER_INT_KER, force,
				FCN_DRV_INT_EN_KER, enabled );
	falcon_write ( efab, &int_en_reg_ker, FCN_INT_EN_REG_KER );	
}

/*******************************************************************************
 *
 *
 * SPI access
 *
 *
 *******************************************************************************/ 


/** Maximum length for a single SPI transaction */
#define FALCON_SPI_MAX_LEN 16

static int
falcon_spi_wait ( struct efab_nic *efab )
{
	efab_oword_t reg;
	int count;

	count = 0;
	do {
		udelay ( 100 );
		falcon_read ( efab, &reg, FCN_EE_SPI_HCMD_REG );
		if ( EFAB_OWORD_FIELD ( reg, FCN_EE_SPI_HCMD_CMD_EN ) == 0 )
			return 0;
	} while ( ++count < 1000 );

	EFAB_ERR ( "Timed out waiting for SPI\n" );
	return -ETIMEDOUT;
}

static int
falcon_spi_rw ( struct spi_bus* bus, struct spi_device *device,
		unsigned int command, int address,
		const void* data_out, void *data_in, size_t len )
{
	struct efab_nic *efab = container_of ( bus, struct efab_nic, spi_bus );
	int address_len, rc, device_id, read_cmd;
	efab_oword_t reg;

	/* falcon_init_spi_device() should have reduced the block size
	 * down so this constraint holds */
	assert ( len <= FALCON_SPI_MAX_LEN );

	/* Is this the FLASH or EEPROM device? */
	if ( device == &efab->spi_flash )
		device_id = FCN_EE_SPI_FLASH;
	else if ( device == &efab->spi_eeprom )
		device_id = FCN_EE_SPI_EEPROM;
	else {
		EFAB_ERR ( "Unknown device %p\n", device );
		return -EINVAL;
	}

	EFAB_TRACE ( "Executing spi command %d on device %d at %d for %zd bytes\n",
		     command, device_id, address, len );

	/* The bus must be idle */
	rc = falcon_spi_wait ( efab );
	if ( rc )
		goto fail1;

	/* Copy data out */
	if ( data_out ) {
		memcpy ( &reg, data_out, len );
		falcon_write ( efab, &reg, FCN_EE_SPI_HDATA_REG );
	}

	/* Program address register */
	if ( address >= 0 ) {
		EFAB_POPULATE_OWORD_1 ( reg, FCN_EE_SPI_HADR_ADR, address );
		falcon_write ( efab, &reg, FCN_EE_SPI_HADR_REG );
	}

	/* Issue command */
	address_len = ( address >= 0 ) ? device->address_len / 8 : 0;
	read_cmd = ( data_in ? FCN_EE_SPI_READ : FCN_EE_SPI_WRITE );
	EFAB_POPULATE_OWORD_7 ( reg,
				FCN_EE_SPI_HCMD_CMD_EN, 1,
				FCN_EE_SPI_HCMD_SF_SEL, device_id,
				FCN_EE_SPI_HCMD_DABCNT, len,
				FCN_EE_SPI_HCMD_READ, read_cmd,
				FCN_EE_SPI_HCMD_DUBCNT, 0,
				FCN_EE_SPI_HCMD_ADBCNT, address_len,
				FCN_EE_SPI_HCMD_ENC, command );
	falcon_write ( efab, &reg, FCN_EE_SPI_HCMD_REG );

	/* Wait for the command to complete */
	rc = falcon_spi_wait ( efab );
	if ( rc )
		goto fail2;

	/* Copy data in */
	if ( data_in ) {
		falcon_read ( efab, &reg, FCN_EE_SPI_HDATA_REG );
		memcpy ( data_in, &reg, len );
	}

	return 0;

fail2:
fail1:
	EFAB_ERR ( "Failed SPI command %d to device %d address 0x%x len 0x%zx\n",
		   command, device_id, address, len );

	return rc;
}

/*******************************************************************************
 *
 *
 * Falcon bit-bashed I2C interface
 *
 *
 *******************************************************************************/ 

static void
falcon_i2c_bit_write ( struct bit_basher *basher, unsigned int bit_id,
		       unsigned long data )
{
	struct efab_nic *efab = container_of ( basher, struct efab_nic,
					       i2c_bb.basher );
	efab_oword_t reg;

	falcon_read ( efab, &reg, FCN_GPIO_CTL_REG_KER );
	switch ( bit_id ) {
	case I2C_BIT_SCL:
		EFAB_SET_OWORD_FIELD ( reg, FCN_GPIO0_OEN, ( data ? 0 : 1 ) );
		break;
	case I2C_BIT_SDA:
		EFAB_SET_OWORD_FIELD ( reg, FCN_GPIO3_OEN, ( data ? 0 : 1 ) );
		break;
	default:
		EFAB_ERR ( "%s bit=%d\n", __func__, bit_id );
		break;
	}

	falcon_write ( efab, &reg,  FCN_GPIO_CTL_REG_KER );
}

static int
falcon_i2c_bit_read ( struct bit_basher *basher, unsigned int bit_id )
{
	struct efab_nic *efab = container_of ( basher, struct efab_nic,
					       i2c_bb.basher );
	efab_oword_t reg;
	
	falcon_read ( efab, &reg, FCN_GPIO_CTL_REG_KER );
	switch ( bit_id ) {
	case I2C_BIT_SCL:
		return EFAB_OWORD_FIELD ( reg, FCN_GPIO0_IN );
		break;
	case I2C_BIT_SDA:
		return EFAB_OWORD_FIELD ( reg, FCN_GPIO3_IN );
		break;
	default:
		EFAB_ERR ( "%s bit=%d\n", __func__, bit_id );
		break;
	}

	return -1;
}

static struct bit_basher_operations falcon_i2c_bit_ops = {
	.read           = falcon_i2c_bit_read,
	.write          = falcon_i2c_bit_write,
};


/*******************************************************************************
 *
 *
 * MDIO access
 *
 *
 *******************************************************************************/ 

static int
falcon_gmii_wait ( struct efab_nic *efab )
{
	efab_dword_t md_stat;
	int count;

	/* wait up to 10ms */
	for (count = 0; count < 1000; count++) {
		falcon_readl ( efab, &md_stat, FCN_MD_STAT_REG_KER );
		if ( EFAB_DWORD_FIELD ( md_stat, FCN_MD_BSY ) == 0 ) {
			if ( EFAB_DWORD_FIELD ( md_stat, FCN_MD_LNFL ) != 0 ||
			     EFAB_DWORD_FIELD ( md_stat, FCN_MD_BSERR ) != 0 ) {
				EFAB_ERR ( "Error from GMII access "
					   EFAB_DWORD_FMT"\n",
					   EFAB_DWORD_VAL ( md_stat ));
				return -EIO;
			}
			return 0;
		}
		udelay(10);
	}

	EFAB_ERR ( "Timed out waiting for GMII\n" );
	return -ETIMEDOUT;
}

static void
falcon_mdio_write ( struct efab_nic *efab, int device,
		    int location, int value )
{
	efab_oword_t reg;

	EFAB_TRACE ( "Writing GMII %d register %02x with %04x\n",
		     device, location, value );

	/* Check MII not currently being accessed */
	if ( falcon_gmii_wait ( efab ) )
		return;

	/* Write the address/ID register */
	EFAB_POPULATE_OWORD_1 ( reg, FCN_MD_PHY_ADR, location );
	falcon_write ( efab, &reg, FCN_MD_PHY_ADR_REG_KER );

	if ( efab->phy_10g ) {
		/* clause45 */
		EFAB_POPULATE_OWORD_2 ( reg, 
					FCN_MD_PRT_ADR, efab->phy_addr,
					FCN_MD_DEV_ADR, device );
	}
	else {
		/* clause22 */
		assert ( device == 0 );

		EFAB_POPULATE_OWORD_2 ( reg,
					FCN_MD_PRT_ADR, efab->phy_addr,
					FCN_MD_DEV_ADR, location );
	}
	falcon_write ( efab, &reg, FCN_MD_ID_REG_KER );
		

	/* Write data */
	EFAB_POPULATE_OWORD_1 ( reg, FCN_MD_TXD, value );
	falcon_write ( efab, &reg, FCN_MD_TXD_REG_KER );

	EFAB_POPULATE_OWORD_2 ( reg,
				FCN_MD_WRC, 1,
				FCN_MD_GC, ( efab->phy_10g ? 0 : 1 ) );
	falcon_write ( efab, &reg, FCN_MD_CS_REG_KER );
		
	/* Wait for data to be written */
	if ( falcon_gmii_wait ( efab ) ) {
		/* Abort the write operation */
		EFAB_POPULATE_OWORD_2 ( reg,
					FCN_MD_WRC, 0,
					FCN_MD_GC, 1);
		falcon_write ( efab, &reg, FCN_MD_CS_REG_KER );
		udelay(10);
	}
}

static int
falcon_mdio_read ( struct efab_nic *efab, int device, int location )
{
	efab_oword_t reg;
	int value;

	/* Check MII not currently being accessed */
	if ( falcon_gmii_wait ( efab ) ) 
		return -1;

	if ( efab->phy_10g ) {
		/* clause45 */
		EFAB_POPULATE_OWORD_1 ( reg, FCN_MD_PHY_ADR, location );
		falcon_write ( efab, &reg, FCN_MD_PHY_ADR_REG_KER );

		EFAB_POPULATE_OWORD_2 ( reg,
					FCN_MD_PRT_ADR, efab->phy_addr,
					FCN_MD_DEV_ADR, device );
		falcon_write ( efab, &reg, FCN_MD_ID_REG_KER);

		/* request data to be read */
		EFAB_POPULATE_OWORD_2 ( reg,
					FCN_MD_RDC, 1,
					FCN_MD_GC, 0 );
	}
	else {
		/* clause22 */
		assert ( device == 0 );

		EFAB_POPULATE_OWORD_2 ( reg,
					FCN_MD_PRT_ADR, efab->phy_addr,
					FCN_MD_DEV_ADR, location );
		falcon_write ( efab, &reg, FCN_MD_ID_REG_KER );

		/* Request data to be read */
		EFAB_POPULATE_OWORD_2 ( reg,
					FCN_MD_RIC, 1,
					FCN_MD_GC, 1 );
	}

	falcon_write ( efab, &reg, FCN_MD_CS_REG_KER );
		
	/* Wait for data to become available */
	if ( falcon_gmii_wait ( efab ) ) {
		/* Abort the read operation */
		EFAB_POPULATE_OWORD_2 ( reg,
					FCN_MD_RIC, 0,
					FCN_MD_GC, 1 );
		falcon_write ( efab, &reg, FCN_MD_CS_REG_KER );
		udelay ( 10 );
		value = -1;
	}
	else {
		/* Read the data */
		falcon_read ( efab, &reg, FCN_MD_RXD_REG_KER );
		value = EFAB_OWORD_FIELD ( reg, FCN_MD_RXD );
	}

	EFAB_TRACE ( "Read from GMII %d register %02x, got %04x\n",
		     device, location, value );

	return value;
}

/*******************************************************************************
 *
 *
 * MAC wrapper
 *
 *
 *******************************************************************************/

static void
falcon_reconfigure_mac_wrapper ( struct efab_nic *efab )
{
	efab_oword_t reg;
	int link_speed;

	if ( efab->link_options & LPA_EF_10000 ) {
		link_speed = 0x3;
	} else if ( efab->link_options & LPA_EF_1000 ) {
		link_speed = 0x2;
	} else if ( efab->link_options & LPA_100 ) {
		link_speed = 0x1;
	} else {
		link_speed = 0x0;
	}
	EFAB_POPULATE_OWORD_5 ( reg,
				FCN_MAC_XOFF_VAL, 0xffff /* datasheet */,
				FCN_MAC_BCAD_ACPT, 1,
				FCN_MAC_UC_PROM, 0,
				FCN_MAC_LINK_STATUS, 1,
				FCN_MAC_SPEED, link_speed );

	falcon_write ( efab, &reg, FCN_MAC0_CTRL_REG_KER );
}

/*******************************************************************************
 *
 *
 * GMAC handling
 *
 *
 *******************************************************************************/

/* GMAC configuration register 1 */
#define GM_CFG1_REG_MAC 0x00
#define GM_SW_RST_LBN 31
#define GM_SW_RST_WIDTH 1
#define GM_RX_FC_EN_LBN 5
#define GM_RX_FC_EN_WIDTH 1
#define GM_TX_FC_EN_LBN 4
#define GM_TX_FC_EN_WIDTH 1
#define GM_RX_EN_LBN 2
#define GM_RX_EN_WIDTH 1
#define GM_TX_EN_LBN 0
#define GM_TX_EN_WIDTH 1

/* GMAC configuration register 2 */
#define GM_CFG2_REG_MAC 0x01
#define GM_PAMBL_LEN_LBN 12
#define GM_PAMBL_LEN_WIDTH 4
#define GM_IF_MODE_LBN 8
#define GM_IF_MODE_WIDTH 2
#define GM_PAD_CRC_EN_LBN 2
#define GM_PAD_CRC_EN_WIDTH 1
#define GM_FD_LBN 0
#define GM_FD_WIDTH 1

/* GMAC maximum frame length register */
#define GM_MAX_FLEN_REG_MAC 0x04
#define GM_MAX_FLEN_LBN 0
#define GM_MAX_FLEN_WIDTH 16

/* GMAC MII management configuration register */
#define GM_MII_MGMT_CFG_REG_MAC 0x08
#define GM_MGMT_CLK_SEL_LBN 0
#define GM_MGMT_CLK_SEL_WIDTH 3

/* GMAC MII management command register */
#define GM_MII_MGMT_CMD_REG_MAC 0x09
#define GM_MGMT_SCAN_CYC_LBN 1
#define GM_MGMT_SCAN_CYC_WIDTH 1
#define GM_MGMT_RD_CYC_LBN 0
#define GM_MGMT_RD_CYC_WIDTH 1

/* GMAC MII management address register */
#define GM_MII_MGMT_ADR_REG_MAC 0x0a
#define GM_MGMT_PHY_ADDR_LBN 8
#define GM_MGMT_PHY_ADDR_WIDTH 5
#define GM_MGMT_REG_ADDR_LBN 0
#define GM_MGMT_REG_ADDR_WIDTH 5

/* GMAC MII management control register */
#define GM_MII_MGMT_CTL_REG_MAC 0x0b
#define GM_MGMT_CTL_LBN 0
#define GM_MGMT_CTL_WIDTH 16

/* GMAC MII management status register */
#define GM_MII_MGMT_STAT_REG_MAC 0x0c
#define GM_MGMT_STAT_LBN 0
#define GM_MGMT_STAT_WIDTH 16

/* GMAC MII management indicators register */
#define GM_MII_MGMT_IND_REG_MAC 0x0d
#define GM_MGMT_BUSY_LBN 0
#define GM_MGMT_BUSY_WIDTH 1

/* GMAC station address register 1 */
#define GM_ADR1_REG_MAC 0x10
#define GM_HWADDR_5_LBN 24
#define GM_HWADDR_5_WIDTH 8
#define GM_HWADDR_4_LBN 16
#define GM_HWADDR_4_WIDTH 8
#define GM_HWADDR_3_LBN 8
#define GM_HWADDR_3_WIDTH 8
#define GM_HWADDR_2_LBN 0
#define GM_HWADDR_2_WIDTH 8

/* GMAC station address register 2 */
#define GM_ADR2_REG_MAC 0x11
#define GM_HWADDR_1_LBN 24
#define GM_HWADDR_1_WIDTH 8
#define GM_HWADDR_0_LBN 16
#define GM_HWADDR_0_WIDTH 8

/* GMAC FIFO configuration register 0 */
#define GMF_CFG0_REG_MAC 0x12
#define GMF_FTFENREQ_LBN 12
#define GMF_FTFENREQ_WIDTH 1
#define GMF_STFENREQ_LBN 11
#define GMF_STFENREQ_WIDTH 1
#define GMF_FRFENREQ_LBN 10
#define GMF_FRFENREQ_WIDTH 1
#define GMF_SRFENREQ_LBN 9
#define GMF_SRFENREQ_WIDTH 1
#define GMF_WTMENREQ_LBN 8
#define GMF_WTMENREQ_WIDTH 1

/* GMAC FIFO configuration register 1 */
#define GMF_CFG1_REG_MAC 0x13
#define GMF_CFGFRTH_LBN 16
#define GMF_CFGFRTH_WIDTH 5
#define GMF_CFGXOFFRTX_LBN 0
#define GMF_CFGXOFFRTX_WIDTH 16

/* GMAC FIFO configuration register 2 */
#define GMF_CFG2_REG_MAC 0x14
#define GMF_CFGHWM_LBN 16
#define GMF_CFGHWM_WIDTH 6
#define GMF_CFGLWM_LBN 0
#define GMF_CFGLWM_WIDTH 6

/* GMAC FIFO configuration register 3 */
#define GMF_CFG3_REG_MAC 0x15
#define GMF_CFGHWMFT_LBN 16
#define GMF_CFGHWMFT_WIDTH 6
#define GMF_CFGFTTH_LBN 0
#define GMF_CFGFTTH_WIDTH 6

/* GMAC FIFO configuration register 4 */
#define GMF_CFG4_REG_MAC 0x16
#define GMF_HSTFLTRFRM_PAUSE_LBN 12
#define GMF_HSTFLTRFRM_PAUSE_WIDTH 12

/* GMAC FIFO configuration register 5 */
#define GMF_CFG5_REG_MAC 0x17
#define GMF_CFGHDPLX_LBN 22
#define GMF_CFGHDPLX_WIDTH 1
#define GMF_CFGBYTMODE_LBN 19
#define GMF_CFGBYTMODE_WIDTH 1
#define GMF_HSTDRPLT64_LBN 18
#define GMF_HSTDRPLT64_WIDTH 1
#define GMF_HSTFLTRFRMDC_PAUSE_LBN 12
#define GMF_HSTFLTRFRMDC_PAUSE_WIDTH 1

static void
falcon_gmac_writel ( struct efab_nic *efab, efab_dword_t *value,
		     unsigned int mac_reg )
{
	efab_oword_t temp;

	EFAB_POPULATE_OWORD_1 ( temp, FCN_MAC_DATA,
				EFAB_DWORD_FIELD ( *value, FCN_MAC_DATA ) );
	falcon_write ( efab, &temp, FALCON_GMAC_REG ( efab, mac_reg ) );
}

static void
falcon_gmac_readl ( struct efab_nic *efab, efab_dword_t *value,
		    unsigned int mac_reg )
{
	efab_oword_t temp;

	falcon_read ( efab, &temp, FALCON_GMAC_REG ( efab, mac_reg ) );
	EFAB_POPULATE_DWORD_1 ( *value, FCN_MAC_DATA,
				EFAB_OWORD_FIELD ( temp, FCN_MAC_DATA ) );
}

static void
mentormac_reset ( struct efab_nic *efab )
{
	efab_dword_t reg;

	/* Take into reset */
	EFAB_POPULATE_DWORD_1 ( reg, GM_SW_RST, 1 );
	falcon_gmac_writel ( efab, &reg, GM_CFG1_REG_MAC );
	udelay ( 1000 );

	/* Take out of reset */
	EFAB_POPULATE_DWORD_1 ( reg, GM_SW_RST, 0 );
	falcon_gmac_writel ( efab, &reg, GM_CFG1_REG_MAC );
	udelay ( 1000 );

	/* Configure GMII interface so PHY is accessible.  Note that
	 * GMII interface is connected only to port 0, and that on
	 * Falcon this is a no-op.
	 */
	EFAB_POPULATE_DWORD_1 ( reg, GM_MGMT_CLK_SEL, 0x4 );
	falcon_gmac_writel ( efab, &reg, GM_MII_MGMT_CFG_REG_MAC );
	udelay ( 10 );
}

static void
mentormac_init ( struct efab_nic *efab )
{
	int pause, if_mode, full_duplex, bytemode, half_duplex;
	efab_dword_t reg;

	/* Configuration register 1 */
	pause = ( efab->link_options & LPA_PAUSE_CAP ) ? 1 : 0;
	if ( ! ( efab->link_options & LPA_EF_DUPLEX ) ) {
		/* Half-duplex operation requires TX flow control */
		pause = 1;
	}
	EFAB_POPULATE_DWORD_4 ( reg,
				GM_TX_EN, 1,
				GM_TX_FC_EN, pause,
				GM_RX_EN, 1,
				GM_RX_FC_EN, 1 );
	falcon_gmac_writel ( efab, &reg, GM_CFG1_REG_MAC );
	udelay ( 10 );

	/* Configuration register 2 */
	if_mode = ( efab->link_options & LPA_EF_1000 ) ? 2 : 1;
	full_duplex = ( efab->link_options & LPA_EF_DUPLEX ) ? 1 : 0;
	EFAB_POPULATE_DWORD_4 ( reg,
				GM_IF_MODE, if_mode,
				GM_PAD_CRC_EN, 1,
				GM_FD, full_duplex,
				GM_PAMBL_LEN, 0x7 /* ? */ );
	falcon_gmac_writel ( efab, &reg, GM_CFG2_REG_MAC );
	udelay ( 10 );

	/* Max frame len register */
	EFAB_POPULATE_DWORD_1 ( reg, GM_MAX_FLEN,
				EFAB_MAX_FRAME_LEN ( ETH_FRAME_LEN ) );
	falcon_gmac_writel ( efab, &reg, GM_MAX_FLEN_REG_MAC );
	udelay ( 10 );

	/* FIFO configuration register 0 */
	EFAB_POPULATE_DWORD_5 ( reg,
				GMF_FTFENREQ, 1,
				GMF_STFENREQ, 1,
				GMF_FRFENREQ, 1,
				GMF_SRFENREQ, 1,
				GMF_WTMENREQ, 1 );
	falcon_gmac_writel ( efab, &reg, GMF_CFG0_REG_MAC );
	udelay ( 10 );

	/* FIFO configuration register 1 */
	EFAB_POPULATE_DWORD_2 ( reg,
				GMF_CFGFRTH, 0x12,
				GMF_CFGXOFFRTX, 0xffff );
	falcon_gmac_writel ( efab, &reg, GMF_CFG1_REG_MAC );
	udelay ( 10 );

	/* FIFO configuration register 2 */
	EFAB_POPULATE_DWORD_2 ( reg,
				GMF_CFGHWM, 0x3f,
				GMF_CFGLWM, 0xa );
	falcon_gmac_writel ( efab, &reg, GMF_CFG2_REG_MAC );
	udelay ( 10 );

	/* FIFO configuration register 3 */
	EFAB_POPULATE_DWORD_2 ( reg,
				GMF_CFGHWMFT, 0x1c,
				GMF_CFGFTTH, 0x08 );
	falcon_gmac_writel ( efab, &reg, GMF_CFG3_REG_MAC );
	udelay ( 10 );

	/* FIFO configuration register 4 */
	EFAB_POPULATE_DWORD_1 ( reg, GMF_HSTFLTRFRM_PAUSE, 1 );
	falcon_gmac_writel ( efab, &reg, GMF_CFG4_REG_MAC );
	udelay ( 10 );
	
	/* FIFO configuration register 5 */
	bytemode = ( efab->link_options & LPA_EF_1000 ) ? 1 : 0;
	half_duplex = ( efab->link_options & LPA_EF_DUPLEX ) ? 0 : 1;
	falcon_gmac_readl ( efab, &reg, GMF_CFG5_REG_MAC );
	EFAB_SET_DWORD_FIELD ( reg, GMF_CFGBYTMODE, bytemode );
	EFAB_SET_DWORD_FIELD ( reg, GMF_CFGHDPLX, half_duplex );
	EFAB_SET_DWORD_FIELD ( reg, GMF_HSTDRPLT64, half_duplex );
	EFAB_SET_DWORD_FIELD ( reg, GMF_HSTFLTRFRMDC_PAUSE, 0 );
	falcon_gmac_writel ( efab, &reg, GMF_CFG5_REG_MAC );
	udelay ( 10 );
	
	/* MAC address */
	EFAB_POPULATE_DWORD_4 ( reg,
				GM_HWADDR_5, efab->mac_addr[5],
				GM_HWADDR_4, efab->mac_addr[4],
				GM_HWADDR_3, efab->mac_addr[3],
				GM_HWADDR_2, efab->mac_addr[2] );
	falcon_gmac_writel ( efab, &reg, GM_ADR1_REG_MAC );
	udelay ( 10 );
	EFAB_POPULATE_DWORD_2 ( reg,
				GM_HWADDR_1, efab->mac_addr[1],
				GM_HWADDR_0, efab->mac_addr[0] );
	falcon_gmac_writel ( efab, &reg, GM_ADR2_REG_MAC );
	udelay ( 10 );
}

static int
falcon_init_gmac ( struct efab_nic *efab )
{
	/* Reset the MAC */
	mentormac_reset ( efab );

	/* Initialise PHY */
	efab->phy_op->init ( efab );

	/* check the link is up */
	if ( !efab->link_up )
		return -EAGAIN;

	/* Initialise MAC */
	mentormac_init ( efab );

	/* reconfigure the MAC wrapper */
	falcon_reconfigure_mac_wrapper ( efab );

	return 0;
}

static struct efab_mac_operations falcon_gmac_operations = {
	.init                   = falcon_init_gmac,
};


/*******************************************************************************
 *
 *
 * XMAC handling
 *
 *
 *******************************************************************************/

/**
 * Write dword to a Falcon XMAC register
 *
 */
static void
falcon_xmac_writel ( struct efab_nic *efab, efab_dword_t *value,
		     unsigned int mac_reg )
{
	efab_oword_t temp;

	EFAB_POPULATE_OWORD_1 ( temp, FCN_MAC_DATA,
				EFAB_DWORD_FIELD ( *value, FCN_MAC_DATA ) );
	falcon_write ( efab, &temp,
		       FALCON_XMAC_REG ( efab, mac_reg ) );
}

/**
 * Read dword from a Falcon XMAC register
 *
 */
static void
falcon_xmac_readl ( struct efab_nic *efab, efab_dword_t *value,
		    unsigned int mac_reg )
{
	efab_oword_t temp;

	falcon_read ( efab, &temp,
		      FALCON_XMAC_REG ( efab, mac_reg ) );
	EFAB_POPULATE_DWORD_1 ( *value, FCN_MAC_DATA,
				EFAB_OWORD_FIELD ( temp, FCN_MAC_DATA ) );
}

/**
 * Configure Falcon XAUI output
 */
static void
falcon_setup_xaui ( struct efab_nic *efab )
{
	efab_dword_t sdctl, txdrv;

	falcon_xmac_readl ( efab, &sdctl, FCN_XX_SD_CTL_REG_MAC );
	EFAB_SET_DWORD_FIELD ( sdctl, FCN_XX_HIDRVD, XX_SD_CTL_DRV_DEFAULT );
	EFAB_SET_DWORD_FIELD ( sdctl, FCN_XX_LODRVD, XX_SD_CTL_DRV_DEFAULT );
	EFAB_SET_DWORD_FIELD ( sdctl, FCN_XX_HIDRVC, XX_SD_CTL_DRV_DEFAULT );
	EFAB_SET_DWORD_FIELD ( sdctl, FCN_XX_LODRVC, XX_SD_CTL_DRV_DEFAULT );
	EFAB_SET_DWORD_FIELD ( sdctl, FCN_XX_HIDRVB, XX_SD_CTL_DRV_DEFAULT );
	EFAB_SET_DWORD_FIELD ( sdctl, FCN_XX_LODRVB, XX_SD_CTL_DRV_DEFAULT );
	EFAB_SET_DWORD_FIELD ( sdctl, FCN_XX_HIDRVA, XX_SD_CTL_DRV_DEFAULT );
	EFAB_SET_DWORD_FIELD ( sdctl, FCN_XX_LODRVA, XX_SD_CTL_DRV_DEFAULT );
	falcon_xmac_writel ( efab, &sdctl, FCN_XX_SD_CTL_REG_MAC );

	EFAB_POPULATE_DWORD_8 ( txdrv,
				FCN_XX_DEQD, XX_TXDRV_DEQ_DEFAULT,
				FCN_XX_DEQC, XX_TXDRV_DEQ_DEFAULT,
				FCN_XX_DEQB, XX_TXDRV_DEQ_DEFAULT,
				FCN_XX_DEQA, XX_TXDRV_DEQ_DEFAULT,
				FCN_XX_DTXD, XX_TXDRV_DTX_DEFAULT,
				FCN_XX_DTXC, XX_TXDRV_DTX_DEFAULT,
				FCN_XX_DTXB, XX_TXDRV_DTX_DEFAULT,
				FCN_XX_DTXA, XX_TXDRV_DTX_DEFAULT);
	falcon_xmac_writel ( efab, &txdrv, FCN_XX_TXDRV_CTL_REG_MAC);
}

static int
falcon_xgmii_status ( struct efab_nic *efab )
{
	efab_dword_t reg;

	if ( efab->pci_revision  < FALCON_REV_B0 )
		return 1;
	/* The ISR latches, so clear it and re-read */
	falcon_xmac_readl ( efab, &reg, FCN_XM_MGT_INT_REG_MAC_B0 );
	falcon_xmac_readl ( efab, &reg, FCN_XM_MGT_INT_REG_MAC_B0 );

	if ( EFAB_DWORD_FIELD ( reg, FCN_XM_LCLFLT ) ||
	     EFAB_DWORD_FIELD ( reg, FCN_XM_RMTFLT ) ) {
		EFAB_TRACE ( "MGT_INT: "EFAB_DWORD_FMT"\n",
			     EFAB_DWORD_VAL ( reg ) );
		return 0;
	}

	return 1;
}

static void
falcon_mask_status_intr ( struct efab_nic *efab, int enable )
{
	efab_dword_t reg;

	if ( efab->pci_revision  < FALCON_REV_B0 )
		return;

	/* Flush the ISR */
	if ( enable )
		falcon_xmac_readl ( efab, &reg, FCN_XM_MGT_INT_REG_MAC_B0 );

	EFAB_POPULATE_DWORD_2 ( reg,
				FCN_XM_MSK_RMTFLT, !enable,
				FCN_XM_MSK_LCLFLT, !enable);
	falcon_xmac_readl ( efab, &reg, FCN_XM_MGT_INT_MSK_REG_MAC_B0 );
}

/**
 * Reset 10G MAC connected to port
 *
 */
static int
falcon_reset_xmac ( struct efab_nic *efab )
{
	efab_dword_t reg;
	int count;

	EFAB_POPULATE_DWORD_1 ( reg, FCN_XM_CORE_RST, 1 );
	falcon_xmac_writel ( efab, &reg, FCN_XM_GLB_CFG_REG_MAC );

	for ( count = 0 ; count < 1000 ; count++ ) {
		udelay ( 10 );
		falcon_xmac_readl ( efab, &reg,
				    FCN_XM_GLB_CFG_REG_MAC );
		if ( EFAB_DWORD_FIELD ( reg, FCN_XM_CORE_RST ) == 0 )
			return 0;
	}
	return -ETIMEDOUT;
}


static int
falcon_reset_xaui ( struct efab_nic *efab )
{
	efab_dword_t reg;
	int count;

	if (!efab->is_asic)
		return 0;

	EFAB_POPULATE_DWORD_1 ( reg, FCN_XX_RST_XX_EN, 1 );
	falcon_xmac_writel ( efab, &reg, FCN_XX_PWR_RST_REG_MAC );

	/* Give some time for the link to establish */
	for (count = 0; count < 1000; count++) { /* wait up to 10ms */
		falcon_xmac_readl ( efab, &reg, FCN_XX_PWR_RST_REG_MAC );
		if ( EFAB_DWORD_FIELD ( reg, FCN_XX_RST_XX_EN ) == 0 ) {
			falcon_setup_xaui ( efab );
			return 0;
		}
		udelay(10);
	}
	EFAB_ERR ( "timed out waiting for XAUI/XGXS reset\n" );
	return -ETIMEDOUT;
}

static int
falcon_xaui_link_ok ( struct efab_nic *efab )
{
	efab_dword_t reg;
	int align_done, lane_status, sync;
	int has_phyxs;
	int link_ok = 1;

	/* Read Falcon XAUI side */
	if ( efab->is_asic ) {
		/* Read link status */
		falcon_xmac_readl ( efab, &reg, FCN_XX_CORE_STAT_REG_MAC );
		align_done = EFAB_DWORD_FIELD ( reg, FCN_XX_ALIGN_DONE );

		sync = EFAB_DWORD_FIELD ( reg, FCN_XX_SYNC_STAT );
		sync = ( sync == FCN_XX_SYNC_STAT_DECODE_SYNCED );
		
		link_ok = align_done && sync;
	}

	/* Clear link status ready for next read */
	EFAB_SET_DWORD_FIELD ( reg, FCN_XX_COMMA_DET, FCN_XX_COMMA_DET_RESET );
	EFAB_SET_DWORD_FIELD ( reg, FCN_XX_CHARERR, FCN_XX_CHARERR_RESET);
	EFAB_SET_DWORD_FIELD ( reg, FCN_XX_DISPERR, FCN_XX_DISPERR_RESET);
	falcon_xmac_writel ( efab, &reg, FCN_XX_CORE_STAT_REG_MAC );

	has_phyxs = ( efab->phy_op->mmds & ( 1 << MDIO_MMD_PHYXS ) );
	if ( link_ok && has_phyxs ) {
		lane_status = falcon_mdio_read ( efab, MDIO_MMD_PHYXS,
						 MDIO_PHYXS_LANE_STATE );
		link_ok = ( lane_status & ( 1 << MDIO_PHYXS_LANE_ALIGNED_LBN ) );

		if (!link_ok )
			EFAB_LOG ( "XGXS lane status: %x\n", lane_status );
	}

	return link_ok;
}

/**
 * Initialise XMAC
 *
 */
static void
falcon_reconfigure_xmac ( struct efab_nic *efab )
{
	efab_dword_t reg;
	int max_frame_len;

	/* Configure MAC - cut-thru mode is hard wired on */
	EFAB_POPULATE_DWORD_3 ( reg,
				FCN_XM_RX_JUMBO_MODE, 1,
				FCN_XM_TX_STAT_EN, 1,
				FCN_XM_RX_STAT_EN, 1);
	falcon_xmac_writel ( efab, &reg, FCN_XM_GLB_CFG_REG_MAC );

	/* Configure TX */
	EFAB_POPULATE_DWORD_6 ( reg, 
				FCN_XM_TXEN, 1,
				FCN_XM_TX_PRMBL, 1,
				FCN_XM_AUTO_PAD, 1,
				FCN_XM_TXCRC, 1,
				FCN_XM_FCNTL, 1,
				FCN_XM_IPG, 0x3 );
	falcon_xmac_writel ( efab, &reg, FCN_XM_TX_CFG_REG_MAC );

	/* Configure RX */
	EFAB_POPULATE_DWORD_4 ( reg,
				FCN_XM_RXEN, 1,
				FCN_XM_AUTO_DEPAD, 0,
				FCN_XM_ACPT_ALL_MCAST, 1,
				FCN_XM_PASS_CRC_ERR, 1 );
	falcon_xmac_writel ( efab, &reg, FCN_XM_RX_CFG_REG_MAC );

	/* Set frame length */
	max_frame_len = EFAB_MAX_FRAME_LEN ( ETH_FRAME_LEN );
	EFAB_POPULATE_DWORD_1 ( reg,
				FCN_XM_MAX_RX_FRM_SIZE, max_frame_len );
	falcon_xmac_writel ( efab, &reg, FCN_XM_RX_PARAM_REG_MAC );
	EFAB_POPULATE_DWORD_2 ( reg,
				FCN_XM_MAX_TX_FRM_SIZE, max_frame_len,
				FCN_XM_TX_JUMBO_MODE, 1 );
	falcon_xmac_writel ( efab, &reg, FCN_XM_TX_PARAM_REG_MAC );

	/* Enable flow control receipt */
	EFAB_POPULATE_DWORD_2 ( reg,
				FCN_XM_PAUSE_TIME, 0xfffe,
				FCN_XM_DIS_FCNTL, 0 );
	falcon_xmac_writel ( efab, &reg, FCN_XM_FC_REG_MAC );

	/* Set MAC address */
	EFAB_POPULATE_DWORD_4 ( reg,
				FCN_XM_ADR_0, efab->mac_addr[0],
				FCN_XM_ADR_1, efab->mac_addr[1],
				FCN_XM_ADR_2, efab->mac_addr[2],
				FCN_XM_ADR_3, efab->mac_addr[3] );
	falcon_xmac_writel ( efab, &reg, FCN_XM_ADR_LO_REG_MAC );
	EFAB_POPULATE_DWORD_2 ( reg,
				FCN_XM_ADR_4, efab->mac_addr[4],
				FCN_XM_ADR_5, efab->mac_addr[5] );
	falcon_xmac_writel ( efab, &reg, FCN_XM_ADR_HI_REG_MAC );
}

static int
falcon_init_xmac ( struct efab_nic *efab )
{
	int count, rc;

	/* Mask the PHY management interrupt */
	falcon_mask_status_intr ( efab, 0 );

	/* Initialise the PHY to instantiate the clock. */
	rc = efab->phy_op->init ( efab );
	if ( rc ) {
		EFAB_ERR ( "unable to initialise PHY\n" );
		goto fail1;
	}

	falcon_reset_xaui ( efab );

	/* Give the PHY and MAC time to faff */
	mdelay ( 100 );

	/* Reset and reconfigure the XMAC */
	rc = falcon_reset_xmac ( efab );
	if ( rc )
		goto fail2;
	falcon_reconfigure_xmac ( efab );
	falcon_reconfigure_mac_wrapper ( efab );
	/**
	 * Now wait for the link to come up. This may take a while
	 * for some slower PHY's.
	 */
	for (count=0; count<50; count++) {
		int link_ok = 1;

		/* Wait a while for the link to come up. */
		mdelay ( 100 );
		if ((count % 5) == 0)
			putchar ( '.' );

		/* Does the PHY think the wire-side link is up? */
		link_ok = mdio_clause45_links_ok ( efab );
		/* Ensure the XAUI link to the PHY is good */
		if ( link_ok ) {
			link_ok = falcon_xaui_link_ok ( efab );
			if ( !link_ok )
				falcon_reset_xaui ( efab );
		}

		/* Check fault indication */
		if ( link_ok )
			link_ok = falcon_xgmii_status ( efab );

		efab->link_up = link_ok;
		if ( link_ok ) {
			/* unmask the status interrupt */
			falcon_mask_status_intr ( efab, 1 );
			return 0;
		}
	}

	/* Link failed to come up, but initialisation was fine. */
	rc = -ETIMEDOUT;

fail2:
fail1:
	return rc;
}

static struct efab_mac_operations falcon_xmac_operations = {
	.init                   = falcon_init_xmac,
};

/*******************************************************************************
 *
 *
 * Null PHY handling
 *
 *
 *******************************************************************************/

static int
falcon_xaui_phy_init ( struct efab_nic *efab )
{
	/* CX4 is always 10000FD only */
	efab->link_options = LPA_EF_10000FULL;

	/* There is no PHY! */
	return 0;
}

static struct efab_phy_operations falcon_xaui_phy_ops = {
	.init                   = falcon_xaui_phy_init,
	.mmds                   = 0,
};


/*******************************************************************************
 *
 *
 * Alaska PHY
 *
 *
 *******************************************************************************/

/**
 * Initialise Alaska PHY
 *
 */
static int
alaska_init ( struct efab_nic *efab )
{
	unsigned int advertised, lpa;

	/* Read link up status */
	efab->link_up = gmii_link_ok ( efab );

	if ( ! efab->link_up )
		return -EIO;

	/* Determine link options from PHY. */
	advertised = gmii_autoneg_advertised ( efab );
	lpa = gmii_autoneg_lpa ( efab );
	efab->link_options = gmii_nway_result ( advertised & lpa );

	return 0;
}

static struct efab_phy_operations falcon_alaska_phy_ops = {
	.init  	    	= alaska_init,
};

/*******************************************************************************
 *
 *
 * xfp
 *
 *
 *******************************************************************************/

#define XFP_REQUIRED_DEVS ( MDIO_MMDREG_DEVS0_PCS    |		\
			    MDIO_MMDREG_DEVS0_PMAPMD |		\
			    MDIO_MMDREG_DEVS0_PHYXS )

static int
falcon_xfp_phy_init ( struct efab_nic *efab )
{
	int rc;

	/* Optical link is always 10000FD only */
	efab->link_options = LPA_EF_10000FULL;

	/* Reset the PHY */
	rc = mdio_clause45_reset_mmd ( efab, MDIO_MMD_PHYXS );
	if ( rc )
		return rc;

	return 0;
}

static struct efab_phy_operations falcon_xfp_phy_ops = {
	.init                   = falcon_xfp_phy_init,
	.mmds                   = XFP_REQUIRED_DEVS,
};

/*******************************************************************************
 *
 *
 * txc43128
 *
 *
 *******************************************************************************/

/* Command register */
#define TXC_GLRGS_GLCMD		(0xc004)
#define TXC_GLCMD_LMTSWRST_LBN	(14)

/* Amplitude on lanes 0+1, 2+3 */
#define  TXC_ALRGS_ATXAMP0	(0xc041)
#define  TXC_ALRGS_ATXAMP1	(0xc042)
/* Bit position of value for lane 0+2, 1+3 */
#define TXC_ATXAMP_LANE02_LBN	(3)
#define TXC_ATXAMP_LANE13_LBN	(11)

#define TXC_ATXAMP_1280_mV	(0)
#define TXC_ATXAMP_1200_mV	(8)
#define TXC_ATXAMP_1120_mV	(12)
#define TXC_ATXAMP_1060_mV	(14)
#define TXC_ATXAMP_0820_mV	(25)
#define TXC_ATXAMP_0720_mV	(26)
#define TXC_ATXAMP_0580_mV	(27)
#define TXC_ATXAMP_0440_mV	(28)

#define TXC_ATXAMP_0820_BOTH	( (TXC_ATXAMP_0820_mV << TXC_ATXAMP_LANE02_LBN) | \
				  (TXC_ATXAMP_0820_mV << TXC_ATXAMP_LANE13_LBN) )

#define TXC_ATXAMP_DEFAULT	(0x6060) /* From databook */

/* Preemphasis on lanes 0+1, 2+3 */
#define  TXC_ALRGS_ATXPRE0	(0xc043)
#define  TXC_ALRGS_ATXPRE1	(0xc044)

#define TXC_ATXPRE_NONE (0)
#define TXC_ATXPRE_DEFAULT	(0x1010) /* From databook */

#define TXC_REQUIRED_DEVS ( MDIO_MMDREG_DEVS0_PCS    |	       \
			    MDIO_MMDREG_DEVS0_PMAPMD |	       \
			    MDIO_MMDREG_DEVS0_PHYXS )

static int
falcon_txc_logic_reset ( struct efab_nic *efab )
{
	int val;
	int tries = 50;

	val = falcon_mdio_read ( efab, MDIO_MMD_PCS, TXC_GLRGS_GLCMD );
	val |= (1 << TXC_GLCMD_LMTSWRST_LBN);
	falcon_mdio_write ( efab, MDIO_MMD_PCS, TXC_GLRGS_GLCMD, val );

	while ( tries--) {
		val = falcon_mdio_read ( efab, MDIO_MMD_PCS, TXC_GLRGS_GLCMD );
		if ( ~val & ( 1 << TXC_GLCMD_LMTSWRST_LBN ) )
			return 0;
		udelay(1);
	}

	EFAB_ERR ( "logic reset failed\n" );

	return -ETIMEDOUT;
}

static int
falcon_txc_phy_init ( struct efab_nic *efab )
{
	int rc;

	/* CX4 is always 10000FD only */
	efab->link_options = LPA_EF_10000FULL;

	/* reset the phy */
	rc = mdio_clause45_reset_mmd ( efab, MDIO_MMD_PMAPMD );
	if ( rc )
		goto fail1;

	rc = mdio_clause45_check_mmds ( efab );
	if ( rc )
		goto fail2;

	/* Turn amplitude down and preemphasis off on the host side
	 * (PHY<->MAC) as this is believed less likely to upset falcon
	 * and no adverse effects have been noted. It probably also 
	 * saves a picowatt or two */

	/* Turn off preemphasis */
	falcon_mdio_write ( efab, MDIO_MMD_PHYXS, TXC_ALRGS_ATXPRE0,
			    TXC_ATXPRE_NONE );
	falcon_mdio_write ( efab, MDIO_MMD_PHYXS, TXC_ALRGS_ATXPRE1,
			    TXC_ATXPRE_NONE );

	/* Turn down the amplitude */
	falcon_mdio_write ( efab, MDIO_MMD_PHYXS, TXC_ALRGS_ATXAMP0,
			    TXC_ATXAMP_0820_BOTH );
	falcon_mdio_write ( efab, MDIO_MMD_PHYXS, TXC_ALRGS_ATXAMP1,
			    TXC_ATXAMP_0820_BOTH );

	/* Set the line side amplitude and preemphasis to the databook
	 * defaults as an erratum causes them to be 0 on at least some
	 * PHY rev.s */
	falcon_mdio_write ( efab, MDIO_MMD_PMAPMD, TXC_ALRGS_ATXPRE0,
			    TXC_ATXPRE_DEFAULT );
	falcon_mdio_write ( efab, MDIO_MMD_PMAPMD, TXC_ALRGS_ATXPRE1,
			    TXC_ATXPRE_DEFAULT );
	falcon_mdio_write ( efab, MDIO_MMD_PMAPMD, TXC_ALRGS_ATXAMP0,
			    TXC_ATXAMP_DEFAULT );
	falcon_mdio_write ( efab, MDIO_MMD_PMAPMD, TXC_ALRGS_ATXAMP1,
			    TXC_ATXAMP_DEFAULT );

	rc = falcon_txc_logic_reset ( efab );
	if ( rc )
		goto fail3;

	return 0;

fail3:
fail2:
fail1:
	return rc;
}

static struct efab_phy_operations falcon_txc_phy_ops = {
	.init                   = falcon_txc_phy_init,
	.mmds                   = TXC_REQUIRED_DEVS,
};

/*******************************************************************************
 *
 *
 * tenxpress
 *
 *
 *******************************************************************************/


#define TENXPRESS_REQUIRED_DEVS ( MDIO_MMDREG_DEVS0_PMAPMD |	\
				  MDIO_MMDREG_DEVS0_PCS    |	\
				  MDIO_MMDREG_DEVS0_PHYXS )

#define	PCS_TEST_SELECT_REG 0xd807	/* PRM 10.5.8 */
#define	CLK312_EN_LBN 3
#define	CLK312_EN_WIDTH 1

#define PCS_CLOCK_CTRL_REG 0xd801
#define PLL312_RST_N_LBN 2

/* Special Software reset register */
#define PMA_PMD_EXT_CTRL_REG 49152
#define PMA_PMD_EXT_SSR_LBN 15

/* Boot status register */
#define PCS_BOOT_STATUS_REG	0xd000
#define PCS_BOOT_FATAL_ERR_LBN	0
#define PCS_BOOT_PROGRESS_LBN	1
#define PCS_BOOT_PROGRESS_WIDTH	2
#define PCS_BOOT_COMPLETE_LBN	3

#define PCS_SOFT_RST2_REG 0xd806
#define SERDES_RST_N_LBN 13
#define XGXS_RST_N_LBN 12

static int
falcon_tenxpress_check_c11 ( struct efab_nic *efab )
{
	int count;
	uint32_t boot_stat;

	/* Check that the C11 CPU has booted */
	for (count=0; count<10; count++) {
		boot_stat = falcon_mdio_read ( efab, MDIO_MMD_PCS,
					       PCS_BOOT_STATUS_REG );
		if ( boot_stat & ( 1 << PCS_BOOT_COMPLETE_LBN ) )
			return 0;

		udelay(10);
	}

	EFAB_ERR ( "C11 failed to boot\n" );
	return -ETIMEDOUT;
}

static int
falcon_tenxpress_phy_init ( struct efab_nic *efab )
{
	int rc, reg;

	/* 10XPRESS is always 10000FD (at the moment) */
	efab->link_options = LPA_EF_10000FULL;

	/* Wait for the blocks to come out of reset */
	rc = mdio_clause45_wait_reset_mmds ( efab );
	if ( rc )
		goto fail1;

	rc = mdio_clause45_check_mmds ( efab );
	if ( rc )
		goto fail2;

	/* Turn on the clock  */
	reg = (1 << CLK312_EN_LBN);
	falcon_mdio_write ( efab, MDIO_MMD_PCS, PCS_TEST_SELECT_REG, reg);

	/* Wait 200ms for the PHY to boot */
	mdelay(200);

	rc = falcon_tenxpress_check_c11 ( efab );
	if ( rc )
		goto fail3;

	return 0;

fail3:
fail2:
fail1:
	return rc;
}

static struct efab_phy_operations falcon_tenxpress_phy_ops = {
	.init                   = falcon_tenxpress_phy_init,
	.mmds                   = TENXPRESS_REQUIRED_DEVS,
};

/*******************************************************************************
 *
 *
 * PM8358
 *
 *
 *******************************************************************************/

/* The PM8358 just presents a DTE XS */
#define PM8358_REQUIRED_DEVS (MDIO_MMDREG_DEVS0_DTEXS)

/* PHY-specific definitions */
/* Master ID and Global Performance Monitor Update */
#define PMC_MASTER_REG (0xd000)
/* Analog Tx Rx settings under software control */
#define PMC_MASTER_ANLG_CTRL (1<< 11)

/* Master Configuration register 2 */
#define PMC_MCONF2_REG	(0xd002)
/* Drive Tx off centre of data eye (1) vs. clock edge (0) */
#define	PMC_MCONF2_TEDGE (1 << 2) 
/* Drive Rx off centre of data eye (1) vs. clock edge (0) */
#define PMC_MCONF2_REDGE (1 << 3)

/* Analog Rx settings */
#define PMC_ANALOG_RX_CFG0   (0xd025)
#define PMC_ANALOG_RX_CFG1   (0xd02d)
#define PMC_ANALOG_RX_CFG2   (0xd035)
#define PMC_ANALOG_RX_CFG3   (0xd03d)


#define PMC_ANALOG_RX_TERM     (1 << 15) /* Bit 15 of RX CFG: 0 for 100 ohms float,
					    1 for 50 to 1.2V */
#define PMC_ANALOG_RX_EQ_MASK (3 << 8)
#define PMC_ANALOG_RX_EQ_NONE (0 << 8)
#define PMC_ANALOG_RX_EQ_HALF (1 << 8)
#define PMC_ANALOG_RX_EQ_FULL (2 << 8)
#define PMC_ANALOG_RX_EQ_RSVD (3 << 8)

static int
falcon_pm8358_phy_init ( struct efab_nic *efab )
{
	int rc, reg, i;

	/* This is a XAUI retimer part */
	efab->link_options = LPA_EF_10000FULL;

	rc = mdio_clause45_reset_mmd ( efab, MDIO_MMDREG_DEVS0_DTEXS );
	if ( rc )
		return rc;
	
	/* Enable software control of analogue settings */
	reg = falcon_mdio_read ( efab, MDIO_MMD_DTEXS,  PMC_MASTER_REG );
	reg |= PMC_MASTER_ANLG_CTRL;
	falcon_mdio_write ( efab, MDIO_MMD_DTEXS, PMC_MASTER_REG, reg );

	/* Turn rx eq on for all channels */
	for (i=0; i< 3; i++) {
		/* The analog CFG registers are evenly spaced 8 apart */
		uint16_t addr = PMC_ANALOG_RX_CFG0 + 8*i;
		reg = falcon_mdio_read ( efab, MDIO_MMD_DTEXS, addr );
		reg = ( reg & ~PMC_ANALOG_RX_EQ_MASK ) | PMC_ANALOG_RX_EQ_FULL;
		falcon_mdio_write ( efab, MDIO_MMD_DTEXS, addr, reg );
	}

	/* Set TEDGE, clear REDGE */
	reg = falcon_mdio_read ( efab, MDIO_MMD_DTEXS, PMC_MCONF2_REG );
	reg = ( reg & ~PMC_MCONF2_REDGE) | PMC_MCONF2_TEDGE;
	falcon_mdio_write ( efab, MDIO_MMD_DTEXS, PMC_MCONF2_REG, reg );

	return 0;
}

static struct efab_phy_operations falcon_pm8358_phy_ops = {
	.init                   = falcon_pm8358_phy_init,
	.mmds                   = PM8358_REQUIRED_DEVS,
};

/*******************************************************************************
 *
 *
 * SFE4001 support
 *
 *
 *******************************************************************************/

#define MAX_TEMP_THRESH 90

/* I2C Expander */
#define PCA9539 0x74

#define P0_IN 0x00
#define P0_OUT 0x02
#define P0_CONFIG 0x06

#define P0_EN_1V0X_LBN 0
#define P0_EN_1V0X_WIDTH 1
#define P0_EN_1V2_LBN 1
#define P0_EN_1V2_WIDTH 1
#define P0_EN_2V5_LBN 2
#define P0_EN_2V5_WIDTH 1
#define P0_EN_3V3X_LBN 3
#define P0_EN_3V3X_WIDTH 1
#define P0_EN_5V_LBN 4
#define P0_EN_5V_WIDTH 1
#define P0_X_TRST_LBN 6
#define P0_X_TRST_WIDTH 1

#define P1_IN 0x01
#define P1_CONFIG 0x07

#define P1_AFE_PWD_LBN 0
#define P1_AFE_PWD_WIDTH 1
#define P1_DSP_PWD25_LBN 1
#define P1_DSP_PWD25_WIDTH 1
#define P1_SPARE_LBN 4
#define P1_SPARE_WIDTH 4

/* Temperature Sensor */
#define MAX6647	0x4e

#define RSL	0x02
#define RLHN	0x05
#define WLHO	0x0b

static struct i2c_device i2c_pca9539 = {
	.dev_addr = PCA9539,
	.dev_addr_len = 1,
	.word_addr_len = 1,
};


static struct i2c_device i2c_max6647 = {
	.dev_addr = MAX6647,
	.dev_addr_len = 1,
	.word_addr_len = 1,
};

static int
sfe4001_init ( struct efab_nic *efab )
{
	struct i2c_interface *i2c = &efab->i2c_bb.i2c;
	efab_dword_t reg;
	uint8_t in, cfg, out;
	int count, rc;

	EFAB_LOG ( "Initialise SFE4001 board\n" );

	/* Ensure XGXS and XAUI SerDes are held in reset */
	EFAB_POPULATE_DWORD_7 ( reg,
				FCN_XX_PWRDNA_EN, 1,
				FCN_XX_PWRDNB_EN, 1,
				FCN_XX_RSTPLLAB_EN, 1,
				FCN_XX_RESETA_EN, 1,
				FCN_XX_RESETB_EN, 1,
				FCN_XX_RSTXGXSRX_EN, 1,
				FCN_XX_RSTXGXSTX_EN, 1 );
	falcon_xmac_writel ( efab, &reg, FCN_XX_PWR_RST_REG_MAC);
	udelay(10);

	/* Set DSP over-temperature alert threshold */
	cfg = MAX_TEMP_THRESH;
	rc = i2c->write ( i2c, &i2c_max6647, WLHO, &cfg, EFAB_BYTE );
	if ( rc )
		goto fail1;

	/* Read it back and verify */
	rc = i2c->read ( i2c, &i2c_max6647, RLHN, &in, EFAB_BYTE );
	if ( rc )
		goto fail2;

	if ( in != MAX_TEMP_THRESH ) {
		EFAB_ERR ( "Unable to verify MAX6647 limit (requested=%d "
			   "confirmed=%d)\n", cfg, in );
		rc = -EIO;
		goto fail3;
	}

	/* Clear any previous over-temperature alert */
	rc = i2c->read ( i2c, &i2c_max6647, RSL, &in, EFAB_BYTE );
	if ( rc )
		goto fail4;

	/* Enable port 0 and 1 outputs on IO expander */
	cfg = 0x00;
	rc = i2c->write ( i2c, &i2c_pca9539, P0_CONFIG, &cfg, EFAB_BYTE );
	if ( rc )
		goto fail5;
	cfg = 0xff & ~(1 << P1_SPARE_LBN);
	rc = i2c->write ( i2c, &i2c_pca9539, P1_CONFIG, &cfg, EFAB_BYTE );
	if ( rc )
		goto fail6;

	/* Turn all power off then wait 1 sec. This ensures PHY is reset */
	out = 0xff & ~((0 << P0_EN_1V2_LBN) | (0 << P0_EN_2V5_LBN) |
		       (0 << P0_EN_3V3X_LBN) | (0 << P0_EN_5V_LBN) |
		       (0 << P0_EN_1V0X_LBN));

	rc = i2c->write ( i2c, &i2c_pca9539, P0_OUT, &out, EFAB_BYTE );
	if ( rc )
		goto fail7;

	mdelay(1000);

	for (count=0; count<20; count++) {
		/* Turn on 1.2V, 2.5V, 3.3V and 5V power rails */
		out = 0xff & ~( (1 << P0_EN_1V2_LBN)  | (1 << P0_EN_2V5_LBN) |
				(1 << P0_EN_3V3X_LBN) | (1 << P0_EN_5V_LBN)  | 
				(1 << P0_X_TRST_LBN) );

		rc = i2c->write ( i2c, &i2c_pca9539, P0_OUT, &out, EFAB_BYTE );
		if ( rc )
			goto fail8;

		mdelay ( 10 );
		
		/* Turn on the 1V power rail */
		out  &= ~( 1 << P0_EN_1V0X_LBN );
		rc = i2c->write ( i2c, &i2c_pca9539, P0_OUT, &out, EFAB_BYTE );
		if ( rc )
			goto fail9;

		EFAB_LOG ( "Waiting for power...(attempt %d)\n", count);
		mdelay ( 1000 );

		/* Check DSP is powered */
		rc = i2c->read ( i2c, &i2c_pca9539, P1_IN, &in, EFAB_BYTE );
		if ( rc )
			goto fail10;

		if ( in & ( 1 << P1_AFE_PWD_LBN ) )
			return 0;
	}

	rc = -ETIMEDOUT;

fail10:
fail9:
fail8:
fail7:
	/* Turn off power rails */
	out = 0xff;
	(void) i2c->write ( i2c, &i2c_pca9539, P0_OUT, &out, EFAB_BYTE );
	/* Disable port 1 outputs on IO expander */
	out = 0xff;
	(void) i2c->write ( i2c, &i2c_pca9539, P1_CONFIG, &out, EFAB_BYTE );
fail6:
	/* Disable port 0 outputs */
	out = 0xff;
	(void) i2c->write ( i2c, &i2c_pca9539, P1_CONFIG, &out, EFAB_BYTE );
fail5:
fail4:
fail3:
fail2:
fail1:
	EFAB_ERR ( "Failed initialising SFE4001 board\n" );
	return rc;
}

static void
sfe4001_fini ( struct efab_nic *efab )
{
	struct i2c_interface *i2c = &efab->i2c_bb.i2c;
	uint8_t in, cfg, out;

	EFAB_ERR ( "Turning off SFE4001\n" );

	/* Turn off all power rails */
	out = 0xff;
	(void) i2c->write ( i2c, &i2c_pca9539, P0_OUT, &out, EFAB_BYTE );

	/* Disable port 1 outputs on IO expander */
	cfg = 0xff;
	(void) i2c->write ( i2c, &i2c_pca9539, P1_CONFIG, &cfg, EFAB_BYTE );

	/* Disable port 0 outputs on IO expander */
	cfg = 0xff;
	(void) i2c->write ( i2c, &i2c_pca9539, P0_CONFIG, &cfg, EFAB_BYTE );

	/* Clear any over-temperature alert */
	(void) i2c->read ( i2c, &i2c_max6647, RSL, &in, EFAB_BYTE );
}

struct efab_board_operations sfe4001_ops = {
	.init		= sfe4001_init,
	.fini		= sfe4001_fini,
};

static int sfe4002_init ( struct efab_nic *efab __attribute__((unused)) )
{
	return 0;
}
static void sfe4002_fini ( struct efab_nic *efab __attribute__((unused)) )
{
}

struct efab_board_operations sfe4002_ops = {
	.init		= sfe4002_init,
	.fini		= sfe4002_fini,
};

static int sfe4003_init ( struct efab_nic *efab __attribute__((unused)) )
{
	return 0;
}
static void sfe4003_fini ( struct efab_nic *efab __attribute__((unused)) )
{
}

struct efab_board_operations sfe4003_ops = {
	.init		= sfe4003_init,
	.fini		= sfe4003_fini,
};

/*******************************************************************************
 *
 *
 * Hardware initialisation
 *
 *
 *******************************************************************************/ 

static void
falcon_free_special_buffer ( void *p )
{
	/* We don't bother cleaning up the buffer table entries -
	 * we're hardly limited */
	free_dma ( p, EFAB_BUF_ALIGN );
}

static void*
falcon_alloc_special_buffer ( struct efab_nic *efab, int bytes,
			      struct efab_special_buffer *entry )
{
	void* buffer;
	int remaining;
	efab_qword_t buf_desc;
	unsigned long dma_addr;

	/* Allocate the buffer, aligned on a buffer address boundary */
	buffer = malloc_dma ( bytes, EFAB_BUF_ALIGN );
	if ( ! buffer )
		return NULL;

	/* Push buffer table entries to back the buffer */
	entry->id = efab->buffer_head;
	entry->dma_addr = dma_addr = virt_to_bus ( buffer );
	assert ( ( dma_addr & ( EFAB_BUF_ALIGN - 1 ) ) == 0 );

	remaining = bytes;
	while ( remaining > 0 ) {
		EFAB_POPULATE_QWORD_3 ( buf_desc,
					FCN_IP_DAT_BUF_SIZE, FCN_IP_DAT_BUF_SIZE_4K,
					FCN_BUF_ADR_FBUF, ( dma_addr >> 12 ),
					FCN_BUF_OWNER_ID_FBUF, 0 );

		falcon_write_sram ( efab, &buf_desc, efab->buffer_head );

		++efab->buffer_head;
		dma_addr += EFAB_BUF_ALIGN;
		remaining -= EFAB_BUF_ALIGN;
	}

	EFAB_TRACE ( "Allocated 0x%x bytes at %p backed by buffer table "
		     "entries 0x%x..0x%x\n", bytes, buffer, entry->id,
		     efab->buffer_head - 1 );

	return buffer;
}

static void
clear_b0_fpga_memories ( struct efab_nic *efab)
{
	efab_oword_t blanko, temp;
	int offset; 

	EFAB_ZERO_OWORD ( blanko );

	/* Clear the address region register */
	EFAB_POPULATE_OWORD_4 ( temp,
				FCN_ADR_REGION0, 0,
				FCN_ADR_REGION1, ( 1 << 16 ),
				FCN_ADR_REGION2, ( 2 << 16 ),
				FCN_ADR_REGION3, ( 3 << 16 ) );
	falcon_write ( efab, &temp, FCN_ADR_REGION_REG_KER );
	
	EFAB_TRACE ( "Clearing filter and RSS tables\n" );

	for ( offset = FCN_RX_FILTER_TBL0 ;
	      offset < FCN_RX_RSS_INDIR_TBL_B0+0x800 ;
	      offset += 0x10 ) {
		falcon_write ( efab, &blanko, offset );
	}

	EFAB_TRACE ( "Wiping buffer tables\n" );

	/* Notice the 8 byte access mode */
	for ( offset = 0x2800000 ;
	      offset < 0x3000000 ;
	      offset += 0x8) {
		_falcon_writel ( efab, 0, offset );
		_falcon_writel ( efab, 0, offset + 4 );
		wmb();
	}
}

static int
falcon_reset ( struct efab_nic *efab )
{
	efab_oword_t glb_ctl_reg_ker;

	/* Initiate software reset */
	EFAB_POPULATE_OWORD_6 ( glb_ctl_reg_ker,
				FCN_PCIE_CORE_RST_CTL, EXCLUDE_FROM_RESET,
				FCN_PCIE_NSTCK_RST_CTL, EXCLUDE_FROM_RESET,
				FCN_PCIE_SD_RST_CTL, EXCLUDE_FROM_RESET,
				FCN_EE_RST_CTL, EXCLUDE_FROM_RESET,
				FCN_EXT_PHY_RST_DUR, 0x7, /* 10ms */
				FCN_SWRST, 1 );

	falcon_write ( efab, &glb_ctl_reg_ker, FCN_GLB_CTL_REG_KER );

	/* Allow 50ms for reset */
	mdelay ( 50 );

	/* Check for device reset complete */
	falcon_read ( efab, &glb_ctl_reg_ker, FCN_GLB_CTL_REG_KER );
	if ( EFAB_OWORD_FIELD ( glb_ctl_reg_ker, FCN_SWRST ) != 0 ) {
		EFAB_ERR ( "Reset failed\n" );
		return -ETIMEDOUT;
	}

	if ( ( efab->pci_revision == FALCON_REV_B0 ) && !efab->is_asic ) {
		clear_b0_fpga_memories ( efab );
	}

	return 0;
}

/** Offset of MAC address within EEPROM or Flash */
#define FALCON_MAC_ADDRESS_OFFSET 0x310

/*
 * Falcon EEPROM structure
 */
#define SF_NV_CONFIG_BASE 0x300
#define SF_NV_CONFIG_EXTRA 0xA0

struct falcon_nv_config_ver2 {
	uint16_t nports;
	uint8_t  port0_phy_addr;
	uint8_t  port0_phy_type;
	uint8_t  port1_phy_addr;
	uint8_t  port1_phy_type;
	uint16_t asic_sub_revision;
	uint16_t board_revision;
	uint8_t mac_location;
};

struct falcon_nv_extra {
	uint16_t magicnumber;
	uint16_t structure_version;
	uint16_t checksum;
	union {
		struct falcon_nv_config_ver2 ver2;
	} ver_specific;
};

#define BOARD_TYPE(_rev) (_rev >> 8)

static void
falcon_probe_nic_variant ( struct efab_nic *efab, struct pci_device *pci )
{
	efab_oword_t altera_build, nic_stat;
	int fpga_version;
	uint8_t revision;

	/* PCI revision */
	pci_read_config_byte ( pci, PCI_REVISION, &revision );
	efab->pci_revision = revision;

	/* Asic vs FPGA */
	falcon_read ( efab, &altera_build, FCN_ALTERA_BUILD_REG_KER );
	fpga_version = EFAB_OWORD_FIELD ( altera_build, FCN_VER_ALL );
	efab->is_asic = (fpga_version == 0);

	/* MAC and PCI type */
	falcon_read ( efab, &nic_stat, FCN_NIC_STAT_REG );
	if ( efab->pci_revision == FALCON_REV_B0 ) {
		efab->phy_10g = EFAB_OWORD_FIELD ( nic_stat, FCN_STRAP_10G );
	}
	else if ( efab->is_asic ) {
		efab->phy_10g = EFAB_OWORD_FIELD ( nic_stat, FCN_STRAP_10G );
	}
	else {
		int minor = EFAB_OWORD_FIELD ( altera_build,  FCN_VER_MINOR );
		efab->phy_10g = ( minor == 0x14 );
	}
}

static void
falcon_init_spi_device ( struct efab_nic *efab, struct spi_device *spi )
{
	/* Falcon's SPI interface only supports reads/writes of up to 16 bytes.
	 * Reduce the nvs block size down to satisfy this - which means callers
	 * should use the nvs_* functions rather than spi_*. */
	if ( spi->nvs.block_size > FALCON_SPI_MAX_LEN )
		spi->nvs.block_size = FALCON_SPI_MAX_LEN;

	spi->bus = &efab->spi_bus;
	efab->spi = spi;
}

static int
falcon_probe_spi ( struct efab_nic *efab )
{
	efab_oword_t nic_stat, gpio_ctl, ee_vpd_cfg;
	int has_flash, has_eeprom, ad9bit;

	falcon_read ( efab, &nic_stat, FCN_NIC_STAT_REG );
	falcon_read ( efab, &gpio_ctl, FCN_GPIO_CTL_REG_KER );
	falcon_read ( efab, &ee_vpd_cfg, FCN_EE_VPD_CFG_REG );

	/* determine if FLASH / EEPROM is present */
	if ( ( efab->pci_revision >= FALCON_REV_B0 ) || efab->is_asic ) {
		has_flash = EFAB_OWORD_FIELD ( nic_stat, FCN_SF_PRST );
		has_eeprom = EFAB_OWORD_FIELD ( nic_stat, FCN_EE_PRST );
	} else {
		has_flash = EFAB_OWORD_FIELD ( gpio_ctl, FCN_FLASH_PRESENT );
		has_eeprom = EFAB_OWORD_FIELD ( gpio_ctl, FCN_EEPROM_PRESENT );
	}
	ad9bit = EFAB_OWORD_FIELD ( ee_vpd_cfg, FCN_EE_VPD_EN_AD9_MODE );

	/* Configure the SPI and I2C bus */
	efab->spi_bus.rw = falcon_spi_rw;
	init_i2c_bit_basher ( &efab->i2c_bb, &falcon_i2c_bit_ops );

	/* Configure the EEPROM SPI device. Generally, an Atmel 25040
	 * (or similar) is used, but this is only possible if there is also
	 * a flash device present to store the boot-time chip configuration.
	 */
	if ( has_eeprom ) {
		if ( has_flash && ad9bit )
			init_at25040 ( &efab->spi_eeprom );
		else
			init_mc25xx640 ( &efab->spi_eeprom );
		falcon_init_spi_device ( efab, &efab->spi_eeprom );
	}

	/* Configure the FLASH SPI device */
	if ( has_flash ) {
		init_at25f1024 ( &efab->spi_flash );
		falcon_init_spi_device ( efab, &efab->spi_flash );
	}

	EFAB_LOG ( "flash is %s, EEPROM is %s%s\n",
		   ( has_flash ? "present" : "absent" ),
		   ( has_eeprom ? "present " : "absent" ),
		   ( has_eeprom ? (ad9bit ? "(9bit)" : "(16bit)") : "") );

	/* The device MUST have flash or eeprom */
	if ( ! efab->spi ) {
		EFAB_ERR ( "Device appears to have no flash or eeprom\n" );
		return -EIO;
	}

	/* If the device has EEPROM attached, then advertise NVO space */
	if ( has_eeprom ) {
		nvo_init ( &efab->nvo, &efab->spi_eeprom.nvs, 0x100, 0xf0,
			   NULL, &efab->netdev->refcnt );
	}

	return 0;
}

static int
falcon_probe_nvram ( struct efab_nic *efab )
{
	struct nvs_device *nvs = &efab->spi->nvs;
	struct falcon_nv_extra nv;
	int rc, board_revision;

	/* Read the MAC address */
	rc = nvs_read ( nvs, FALCON_MAC_ADDRESS_OFFSET,
			efab->mac_addr, ETH_ALEN );
	if ( rc )
		return rc;

	/* Poke through the NVRAM structure for the PHY type. */
	rc = nvs_read ( nvs, SF_NV_CONFIG_BASE + SF_NV_CONFIG_EXTRA,
			&nv, sizeof ( nv ) );
	if ( rc )
		return rc;

	/* Handle each supported NVRAM version */
	if ( ( le16_to_cpu ( nv.magicnumber ) == FCN_NV_MAGIC_NUMBER ) &&
	     ( le16_to_cpu ( nv.structure_version ) >= 2 ) ) {
		struct falcon_nv_config_ver2* ver2 = &nv.ver_specific.ver2;
		
		/* Get the PHY type */
		efab->phy_addr = le16_to_cpu ( ver2->port0_phy_addr );
		efab->phy_type = le16_to_cpu ( ver2->port0_phy_type );
		board_revision = le16_to_cpu ( ver2->board_revision );
	}
	else {
		EFAB_ERR ( "NVram is not recognised\n" );
		return -EINVAL;
	}

	efab->board_type = BOARD_TYPE ( board_revision );
	
	EFAB_TRACE ( "Falcon board %d phy %d @ addr %d\n",
		     efab->board_type, efab->phy_type, efab->phy_addr );

	/* Patch in the board operations */
	switch ( efab->board_type ) {
	case EFAB_BOARD_SFE4001:
		efab->board_op = &sfe4001_ops;
		break;
	case EFAB_BOARD_SFE4002:
		efab->board_op = &sfe4002_ops;
		break;
	case EFAB_BOARD_SFE4003:
		efab->board_op = &sfe4003_ops;
		break;
	default:
		EFAB_ERR ( "Unrecognised board type\n" );
		return -EINVAL;
	}

	/* Patch in MAC operations */
	if ( efab->phy_10g )
		efab->mac_op = &falcon_xmac_operations;
	else
		efab->mac_op = &falcon_gmac_operations;

	/* Hook in the PHY ops */
	switch ( efab->phy_type ) {
	case PHY_TYPE_10XPRESS:
		efab->phy_op = &falcon_tenxpress_phy_ops;
		break;
	case PHY_TYPE_CX4:
		efab->phy_op = &falcon_xaui_phy_ops;
		break;
	case PHY_TYPE_XFP:
		efab->phy_op = &falcon_xfp_phy_ops;
		break;
	case PHY_TYPE_CX4_RTMR:
		efab->phy_op = &falcon_txc_phy_ops;
		break;
	case PHY_TYPE_PM8358:
		efab->phy_op = &falcon_pm8358_phy_ops;
		break;
	case PHY_TYPE_1GIG_ALASKA:
		efab->phy_op = &falcon_alaska_phy_ops;
		break;
	default:
		EFAB_ERR ( "Unknown PHY type: %d\n", efab->phy_type );
		return -EINVAL;
	}

	return 0;
}

static int
falcon_init_sram ( struct efab_nic *efab )
{
	efab_oword_t reg;
	int count;

	/* use card in internal SRAM mode */
	falcon_read ( efab, &reg, FCN_NIC_STAT_REG );
	EFAB_SET_OWORD_FIELD ( reg, FCN_ONCHIP_SRAM, 1 );
	falcon_write ( efab, &reg, FCN_NIC_STAT_REG );

	/* Deactivate any external SRAM that might be present */
	EFAB_POPULATE_OWORD_2 ( reg, 
				FCN_GPIO1_OEN, 1,
				FCN_GPIO1_OUT, 1 );
	falcon_write ( efab, &reg, FCN_GPIO_CTL_REG_KER );

	/* Initiate SRAM reset */
	EFAB_POPULATE_OWORD_2 ( reg,
				FCN_SRAM_OOB_BT_INIT_EN, 1,
				FCN_SRM_NUM_BANKS_AND_BANK_SIZE, 0 );
	falcon_write ( efab, &reg, FCN_SRM_CFG_REG_KER );

	/* Wait for SRAM reset to complete */
	count = 0;
	do {
		/* SRAM reset is slow; expect around 16ms */
		mdelay ( 20 );

		/* Check for reset complete */
		falcon_read ( efab, &reg, FCN_SRM_CFG_REG_KER );
		if ( !EFAB_OWORD_FIELD ( reg, FCN_SRAM_OOB_BT_INIT_EN ) )
			return 0;
	} while (++count < 20);	/* wait up to 0.4 sec */

	EFAB_ERR ( "timed out waiting for SRAM reset\n");
	return -ETIMEDOUT;
}

static void
falcon_setup_nic ( struct efab_nic *efab )
{
	efab_dword_t timer_cmd;
	efab_oword_t reg;
	int tx_fc, xoff_thresh, xon_thresh;

	/* bug5129: Clear the parity enables on the TX data fifos as 
	 * they produce false parity errors because of timing issues 
	 */
	falcon_read ( efab, &reg, FCN_SPARE_REG_KER );
	EFAB_SET_OWORD_FIELD ( reg, FCN_MEM_PERR_EN_TX_DATA, 0 );
	falcon_write ( efab, &reg, FCN_SPARE_REG_KER );
	
	/* Set up TX and RX descriptor caches in SRAM */
	EFAB_POPULATE_OWORD_1 ( reg, FCN_SRM_TX_DC_BASE_ADR, 0x130000 );
	falcon_write ( efab, &reg, FCN_SRM_TX_DC_CFG_REG_KER );
	EFAB_POPULATE_OWORD_1 ( reg, FCN_TX_DC_SIZE, 1 /* 16 descriptors */ );
	falcon_write ( efab, &reg, FCN_TX_DC_CFG_REG_KER );
	EFAB_POPULATE_OWORD_1 ( reg, FCN_SRM_RX_DC_BASE_ADR, 0x100000 );
	falcon_write ( efab, &reg, FCN_SRM_RX_DC_CFG_REG_KER );
	EFAB_POPULATE_OWORD_1 ( reg, FCN_RX_DC_SIZE, 2 /* 32 descriptors */ );
	falcon_write ( efab, &reg, FCN_RX_DC_CFG_REG_KER );
	
	/* Set number of RSS CPUs
	 * bug7244: Increase filter depth to reduce RX_RESET likelihood
	 */
	EFAB_POPULATE_OWORD_5 ( reg,
				FCN_NUM_KER, 0,
				FCN_UDP_FULL_SRCH_LIMIT, 8,
                                FCN_UDP_WILD_SRCH_LIMIT, 8,
                                FCN_TCP_WILD_SRCH_LIMIT, 8,
                                FCN_TCP_FULL_SRCH_LIMIT, 8);
	falcon_write ( efab, &reg, FCN_RX_FILTER_CTL_REG_KER );
	udelay ( 1000 );

	/* Setup RX.  Wait for descriptor is broken and must
	 * be disabled.  RXDP recovery shouldn't be needed, but is.
	 * disable ISCSI parsing because we don't need it
	 */
	falcon_read ( efab, &reg, FCN_RX_SELF_RST_REG_KER );
	EFAB_SET_OWORD_FIELD ( reg, FCN_RX_NODESC_WAIT_DIS, 1 );
	EFAB_SET_OWORD_FIELD ( reg, FCN_RX_RECOVERY_EN, 1 );
	EFAB_SET_OWORD_FIELD ( reg, FCN_RX_ISCSI_DIS, 1 );
	falcon_write ( efab, &reg, FCN_RX_SELF_RST_REG_KER );
	
	/* Determine recommended flow control settings. *
	 * Flow control is qualified on B0 and A1/1G, not on A1/10G */
	if ( efab->pci_revision == FALCON_REV_B0 ) {
		tx_fc = 1;
		xoff_thresh = 54272;  /* ~80Kb - 3*max MTU */
		xon_thresh = 27648; /* ~3*max MTU */
	}
	else if ( !efab->phy_10g ) {
		tx_fc = 1;
		xoff_thresh = 2048;
		xon_thresh = 512;
	}
	else {
		tx_fc = xoff_thresh = xon_thresh = 0;
	}

	/* Setup TX and RX */
	falcon_read ( efab, &reg, FCN_TX_CFG2_REG_KER );
	EFAB_SET_OWORD_FIELD ( reg, FCN_TX_DIS_NON_IP_EV, 1 );
	falcon_write ( efab, &reg, FCN_TX_CFG2_REG_KER );

	falcon_read ( efab, &reg, FCN_RX_CFG_REG_KER );
	EFAB_SET_OWORD_FIELD_VER ( efab, reg, FCN_RX_USR_BUF_SIZE,
				   (3*4096) / 32 );
	if ( efab->pci_revision == FALCON_REV_B0)
		EFAB_SET_OWORD_FIELD ( reg, FCN_RX_INGR_EN_B0, 1 );
	EFAB_SET_OWORD_FIELD_VER ( efab, reg, FCN_RX_XON_MAC_TH,
				   xon_thresh / 256);
	EFAB_SET_OWORD_FIELD_VER ( efab, reg, FCN_RX_XOFF_MAC_TH,
				   xoff_thresh / 256);
	EFAB_SET_OWORD_FIELD_VER ( efab, reg, FCN_RX_XOFF_MAC_EN, tx_fc);
	falcon_write ( efab, &reg, FCN_RX_CFG_REG_KER );

	/* Set timer register */
	EFAB_POPULATE_DWORD_2 ( timer_cmd,
				FCN_TIMER_MODE, FCN_TIMER_MODE_DIS,
				FCN_TIMER_VAL, 0 );
	falcon_writel ( efab, &timer_cmd, FCN_TIMER_CMD_REG_KER );
}

static void
falcon_init_resources ( struct efab_nic *efab )
{
	struct efab_ev_queue *ev_queue = &efab->ev_queue;
	struct efab_rx_queue *rx_queue = &efab->rx_queue;
	struct efab_tx_queue *tx_queue = &efab->tx_queue;

	efab_oword_t reg;
	int jumbo;

	/* Initialise the ptrs */
	tx_queue->read_ptr = tx_queue->write_ptr = 0;
	rx_queue->read_ptr = rx_queue->write_ptr = 0;
	ev_queue->read_ptr = 0;

	/* Push the event queue to the hardware */
	EFAB_POPULATE_OWORD_3 ( reg,
				FCN_EVQ_EN, 1,
				FCN_EVQ_SIZE, FQS(FCN_EVQ, EFAB_EVQ_SIZE),
				FCN_EVQ_BUF_BASE_ID, ev_queue->entry.id );
	falcon_write ( efab, &reg, 
		       FCN_REVISION_REG ( efab, FCN_EVQ_PTR_TBL_KER ) );
	
	/* Push the tx queue to the hardware */
	EFAB_POPULATE_OWORD_8 ( reg,
				FCN_TX_DESCQ_EN, 1,
				FCN_TX_ISCSI_DDIG_EN, 0,
				FCN_TX_ISCSI_DDIG_EN, 0,
				FCN_TX_DESCQ_BUF_BASE_ID, tx_queue->entry.id,
				FCN_TX_DESCQ_EVQ_ID, 0,
				FCN_TX_DESCQ_SIZE, FQS(FCN_TX_DESCQ, EFAB_TXD_SIZE),
				FCN_TX_DESCQ_TYPE, 0 /* kernel queue */,
				FCN_TX_NON_IP_DROP_DIS_B0, 1 );
	falcon_write ( efab, &reg, 
		       FCN_REVISION_REG ( efab, FCN_TX_DESC_PTR_TBL_KER ) );
	
	/* Push the rx queue to the hardware */
	jumbo = ( efab->pci_revision == FALCON_REV_B0 ) ? 0 : 1;
	EFAB_POPULATE_OWORD_8 ( reg,
				FCN_RX_ISCSI_DDIG_EN, 0,
				FCN_RX_ISCSI_HDIG_EN, 0,
				FCN_RX_DESCQ_BUF_BASE_ID, rx_queue->entry.id,
				FCN_RX_DESCQ_EVQ_ID, 0,
				FCN_RX_DESCQ_SIZE, FQS(FCN_RX_DESCQ, EFAB_RXD_SIZE),
				FCN_RX_DESCQ_TYPE, 0 /* kernel queue */,
				FCN_RX_DESCQ_JUMBO, jumbo,
				FCN_RX_DESCQ_EN, 1 );
	falcon_write ( efab, &reg,
		       FCN_REVISION_REG ( efab, FCN_RX_DESC_PTR_TBL_KER ) );

	/* Program INT_ADR_REG_KER */
	EFAB_POPULATE_OWORD_1 ( reg,
				FCN_INT_ADR_KER, virt_to_bus ( &efab->int_ker ) );
	falcon_write ( efab, &reg, FCN_INT_ADR_REG_KER );

	/* Ack the event queue */
	falcon_eventq_read_ack ( efab, ev_queue );
}

static void
falcon_fini_resources ( struct efab_nic *efab )
{
	efab_oword_t cmd;
	
	/* Disable interrupts */
	falcon_interrupts ( efab, 0, 0 );

	/* Flush the dma queues */
	EFAB_POPULATE_OWORD_2 ( cmd,
				FCN_TX_FLUSH_DESCQ_CMD, 1,
				FCN_TX_FLUSH_DESCQ, 0 );
	falcon_write ( efab, &cmd, 
		       FCN_REVISION_REG ( efab, FCN_TX_DESC_PTR_TBL_KER ) );

	EFAB_POPULATE_OWORD_2 ( cmd,
				FCN_RX_FLUSH_DESCQ_CMD, 1,
				FCN_RX_FLUSH_DESCQ, 0 );
	falcon_write ( efab, &cmd,
		       FCN_REVISION_REG ( efab, FCN_RX_DESC_PTR_TBL_KER ) );

	mdelay ( 100 );

	/* Remove descriptor rings from card */
	EFAB_ZERO_OWORD ( cmd );
	falcon_write ( efab, &cmd, 
		       FCN_REVISION_REG ( efab, FCN_TX_DESC_PTR_TBL_KER ) );
	falcon_write ( efab, &cmd, 
		       FCN_REVISION_REG ( efab, FCN_RX_DESC_PTR_TBL_KER ) );
	falcon_write ( efab, &cmd, 
		       FCN_REVISION_REG ( efab, FCN_EVQ_PTR_TBL_KER ) );
}

/*******************************************************************************
 *
 *
 * Hardware rx path
 *
 *
 *******************************************************************************/

static void
falcon_build_rx_desc ( falcon_rx_desc_t *rxd, struct io_buffer *iob )
{
	EFAB_POPULATE_QWORD_2 ( *rxd,
				FCN_RX_KER_BUF_SIZE, EFAB_RX_BUF_SIZE,
				FCN_RX_KER_BUF_ADR, virt_to_bus ( iob->data ) );
}

static void
falcon_notify_rx_desc ( struct efab_nic *efab, struct efab_rx_queue *rx_queue )
{
	efab_dword_t reg;
	int ptr = rx_queue->write_ptr % EFAB_RXD_SIZE;

	EFAB_POPULATE_DWORD_1 ( reg, FCN_RX_DESC_WPTR_DWORD, ptr );
	falcon_writel ( efab, &reg, FCN_RX_DESC_UPD_REG_KER_DWORD );
}


/*******************************************************************************
 *
 *
 * Hardware tx path
 *
 *
 *******************************************************************************/

static void
falcon_build_tx_desc ( falcon_tx_desc_t *txd, struct io_buffer *iob )
{
	EFAB_POPULATE_QWORD_2 ( *txd,
				FCN_TX_KER_BYTE_CNT, iob_len ( iob ),
				FCN_TX_KER_BUF_ADR, virt_to_bus ( iob->data ) );
}

static void
falcon_notify_tx_desc ( struct efab_nic *efab,
			struct efab_tx_queue *tx_queue )
{
	efab_dword_t reg;
	int ptr = tx_queue->write_ptr % EFAB_TXD_SIZE;

	EFAB_POPULATE_DWORD_1 ( reg, FCN_TX_DESC_WPTR_DWORD, ptr );
	falcon_writel ( efab, &reg, FCN_TX_DESC_UPD_REG_KER_DWORD );
}


/*******************************************************************************
 *
 *
 * Software receive interface
 *
 *
 *******************************************************************************/ 

static int
efab_fill_rx_queue ( struct efab_nic *efab,
		     struct efab_rx_queue *rx_queue )
{
	int fill_level = rx_queue->write_ptr - rx_queue->read_ptr;
	int space = EFAB_NUM_RX_DESC - fill_level - 1;
	int pushed = 0;

	while ( space ) {
		int buf_id = rx_queue->write_ptr % EFAB_NUM_RX_DESC;
		int desc_id = rx_queue->write_ptr % EFAB_RXD_SIZE;
		struct io_buffer *iob;
		falcon_rx_desc_t *rxd;

		assert ( rx_queue->buf[buf_id] == NULL );
		iob = alloc_iob ( EFAB_RX_BUF_SIZE );
		if ( !iob )
			break;

		EFAB_TRACE ( "pushing rx_buf[%d] iob %p data %p\n",
			     buf_id, iob, iob->data );

		rx_queue->buf[buf_id] = iob;
		rxd = rx_queue->ring + desc_id;
		falcon_build_rx_desc ( rxd, iob );
		++rx_queue->write_ptr;
		++pushed;
		--space;
	}

	if ( pushed ) {
		/* Push the ptr to hardware */
		falcon_notify_rx_desc ( efab, rx_queue );

		fill_level = rx_queue->write_ptr - rx_queue->read_ptr;
		EFAB_TRACE ( "pushed %d rx buffers to fill level %d\n",
			     pushed, fill_level );
	}

	if ( fill_level == 0 )
		return -ENOMEM;
	return 0;
}
	
static void
efab_receive ( struct efab_nic *efab, unsigned int id, int len, int drop )
{
	struct efab_rx_queue *rx_queue = &efab->rx_queue;
	struct io_buffer *iob;
	unsigned int read_ptr = rx_queue->read_ptr % EFAB_RXD_SIZE;
	unsigned int buf_ptr = rx_queue->read_ptr % EFAB_NUM_RX_DESC;

	assert ( id == read_ptr );
	
	/* Pop this rx buffer out of the software ring */
	iob = rx_queue->buf[buf_ptr];
	rx_queue->buf[buf_ptr] = NULL;

	EFAB_TRACE ( "popping rx_buf[%d] iob %p data %p with %d bytes %s\n",
		     id, iob, iob->data, len, drop ? "bad" : "ok" );

	/* Pass the packet up if required */
	if ( drop )
		free_iob ( iob );
	else {
		iob_put ( iob, len );
		netdev_rx ( efab->netdev, iob );
	}

	++rx_queue->read_ptr;
}

/*******************************************************************************
 *
 *
 * Software transmit interface
 *
 *
 *******************************************************************************/ 

static int
efab_transmit ( struct net_device *netdev, struct io_buffer *iob )
{
	struct efab_nic *efab = netdev_priv ( netdev );
	struct efab_tx_queue *tx_queue = &efab->tx_queue;
	int fill_level, space;
	falcon_tx_desc_t *txd;
	int buf_id;

	fill_level = tx_queue->write_ptr - tx_queue->read_ptr;
	space = EFAB_TXD_SIZE - fill_level - 1;
	if ( space < 1 )
		return -ENOBUFS;

	/* Save the iobuffer for later completion */
	buf_id = tx_queue->write_ptr % EFAB_TXD_SIZE;
	assert ( tx_queue->buf[buf_id] == NULL );
	tx_queue->buf[buf_id] = iob;

	EFAB_TRACE ( "tx_buf[%d] for iob %p data %p len %zd\n",
		     buf_id, iob, iob->data, iob_len ( iob ) );

	/* Form the descriptor, and push it to hardware */
	txd = tx_queue->ring + buf_id;
	falcon_build_tx_desc ( txd, iob );
	++tx_queue->write_ptr;
	falcon_notify_tx_desc ( efab, tx_queue );

	return 0;
}

static int
efab_transmit_done ( struct efab_nic *efab, int id )
{
	struct efab_tx_queue *tx_queue = &efab->tx_queue;
	unsigned int read_ptr, stop;

	/* Complete all buffers from read_ptr up to and including id */
	read_ptr = tx_queue->read_ptr % EFAB_TXD_SIZE;
	stop = ( id + 1 ) % EFAB_TXD_SIZE;

	while ( read_ptr != stop ) {
		struct io_buffer *iob = tx_queue->buf[read_ptr];
		assert ( iob );

		/* Complete the tx buffer */
		if ( iob )
			netdev_tx_complete ( efab->netdev, iob );
		tx_queue->buf[read_ptr] = NULL;
		
		++tx_queue->read_ptr;
		read_ptr = tx_queue->read_ptr % EFAB_TXD_SIZE;
	}

	return 0;
}

/*******************************************************************************
 *
 *
 * Hardware event path
 *
 *
 *******************************************************************************/

static void
falcon_clear_interrupts ( struct efab_nic *efab )
{
	efab_dword_t reg;

	if ( efab->pci_revision == FALCON_REV_B0 ) {
		/* read the ISR */
		falcon_readl( efab, &reg, INT_ISR0_B0 );
	}
	else {
		/* write to the INT_ACK register */
		EFAB_ZERO_DWORD ( reg );
		falcon_writel ( efab, &reg, FCN_INT_ACK_KER_REG_A1 );
		mb();
		falcon_readl ( efab, &reg,
			       WORK_AROUND_BROKEN_PCI_READS_REG_KER_A1 );
	}
}

static void
falcon_handle_event ( struct efab_nic *efab, falcon_event_t *evt )
{
	int ev_code, desc_ptr, len, drop;

	/* Decode event */
	ev_code = EFAB_QWORD_FIELD ( *evt, FCN_EV_CODE );
	switch ( ev_code ) {
	case FCN_TX_IP_EV_DECODE:
		desc_ptr = EFAB_QWORD_FIELD ( *evt, FCN_TX_EV_DESC_PTR );
		efab_transmit_done ( efab, desc_ptr );
		break;
	
	case FCN_RX_IP_EV_DECODE:
		desc_ptr = EFAB_QWORD_FIELD ( *evt, FCN_RX_EV_DESC_PTR );
		len = EFAB_QWORD_FIELD ( *evt, FCN_RX_EV_BYTE_CNT );
		drop = !EFAB_QWORD_FIELD ( *evt, FCN_RX_EV_PKT_OK );

		efab_receive ( efab, desc_ptr, len, drop );
		break;

	default:
		EFAB_TRACE ( "Unknown event type %d\n", ev_code );
		break;
	}
}

/*******************************************************************************
 *
 *
 * Software (polling) interrupt handler
 *
 *
 *******************************************************************************/

static void
efab_poll ( struct net_device *netdev )
{
	struct efab_nic *efab = netdev_priv ( netdev );
	struct efab_ev_queue *ev_queue = &efab->ev_queue;
	struct efab_rx_queue *rx_queue = &efab->rx_queue;
	falcon_event_t *evt;

	/* Read the event queue by directly looking for events
	 * (we don't even bother to read the eventq write ptr) */
	evt = ev_queue->ring + ev_queue->read_ptr;
	while ( falcon_event_present ( evt ) ) {
		
		EFAB_TRACE ( "Event at index 0x%x address %p is "
			     EFAB_QWORD_FMT "\n", ev_queue->read_ptr,
			     evt, EFAB_QWORD_VAL ( *evt ) );
		
		falcon_handle_event ( efab, evt );
		
		/* Clear the event */
		EFAB_SET_QWORD ( *evt );
	
		/* Move to the next event. We don't ack the event
		 * queue until the end */
		ev_queue->read_ptr = ( ( ev_queue->read_ptr + 1 ) %
				       EFAB_EVQ_SIZE );
		evt = ev_queue->ring + ev_queue->read_ptr;
	}

	/* Push more buffers if needed */
	(void) efab_fill_rx_queue ( efab, rx_queue );

	/* Clear any pending interrupts */
	falcon_clear_interrupts ( efab );

	/* Ack the event queue */
	falcon_eventq_read_ack ( efab, ev_queue );
}

static void
efab_irq ( struct net_device *netdev, int enable )
{
	struct efab_nic *efab = netdev_priv ( netdev );
	struct efab_ev_queue *ev_queue = &efab->ev_queue;

	switch ( enable ) {
	case 0:
		falcon_interrupts ( efab, 0, 0 );
		break;
	case 1:
		falcon_interrupts ( efab, 1, 0 );
		falcon_eventq_read_ack ( efab, ev_queue );
		break;
	case 2:
		falcon_interrupts ( efab, 1, 1 );
		break;
	}
}

/*******************************************************************************
 *
 *
 * Software open/close
 *
 *
 *******************************************************************************/

static void
efab_free_resources ( struct efab_nic *efab )
{
	struct efab_ev_queue *ev_queue = &efab->ev_queue;
	struct efab_rx_queue *rx_queue = &efab->rx_queue;
	struct efab_tx_queue *tx_queue = &efab->tx_queue;
	int i;

	for ( i = 0; i < EFAB_NUM_RX_DESC; i++ ) {
		if ( rx_queue->buf[i] )
			free_iob ( rx_queue->buf[i] );
	}

	for ( i = 0; i < EFAB_TXD_SIZE; i++ ) {
		if ( tx_queue->buf[i] )
			netdev_tx_complete ( efab->netdev,  tx_queue->buf[i] );
	}

	if ( rx_queue->ring )
		falcon_free_special_buffer ( rx_queue->ring );

	if ( tx_queue->ring )
		falcon_free_special_buffer ( tx_queue->ring );

	if ( ev_queue->ring )
		falcon_free_special_buffer ( ev_queue->ring );

	memset ( rx_queue, 0, sizeof ( *rx_queue ) );
	memset ( tx_queue, 0, sizeof ( *tx_queue ) );
	memset ( ev_queue, 0, sizeof ( *ev_queue ) );

	/* Ensure subsequent buffer allocations start at id 0 */
	efab->buffer_head = 0;
}

static int
efab_alloc_resources ( struct efab_nic *efab )
{
	struct efab_ev_queue *ev_queue = &efab->ev_queue;
	struct efab_rx_queue *rx_queue = &efab->rx_queue;
	struct efab_tx_queue *tx_queue = &efab->tx_queue;
	size_t bytes;

	/* Allocate the hardware event queue */
	bytes = sizeof ( falcon_event_t ) * EFAB_TXD_SIZE;
	ev_queue->ring = falcon_alloc_special_buffer ( efab, bytes,
						       &ev_queue->entry );
	if ( !ev_queue->ring )
		goto fail1;

	/* Initialise the hardware event queue */
	memset ( ev_queue->ring, 0xff, bytes );

	/* Allocate the hardware tx queue */
	bytes = sizeof ( falcon_tx_desc_t ) * EFAB_TXD_SIZE;
	tx_queue->ring = falcon_alloc_special_buffer ( efab, bytes,
						       &tx_queue->entry );
	if ( ! tx_queue->ring )
		goto fail2;

	/* Allocate the hardware rx queue */
	bytes = sizeof ( falcon_rx_desc_t ) * EFAB_RXD_SIZE;
	rx_queue->ring = falcon_alloc_special_buffer ( efab, bytes,
						       &rx_queue->entry );
	if ( ! rx_queue->ring )
		goto fail3;

	return 0;

fail3:
	falcon_free_special_buffer ( tx_queue->ring );
	tx_queue->ring = NULL;
fail2:
	falcon_free_special_buffer ( ev_queue->ring );
	ev_queue->ring = NULL;
fail1:
	return -ENOMEM;
}

static int
efab_init_mac ( struct efab_nic *efab )
{
	int count, rc;

	/* This can take several seconds */
	EFAB_LOG ( "Waiting for link..\n" );
	for ( count=0; count<5; count++ ) {
		rc = efab->mac_op->init ( efab );
		if ( rc ) {
			EFAB_ERR ( "Failed reinitialising MAC, error %s\n",
				strerror ( rc ));
			return rc;
		}

		/* Sleep for 2s to wait for the link to settle, either
		 * because we want to use it, or because we're about
		 * to reset the mac anyway
		 */
		sleep ( 2 );

		if ( ! efab->link_up ) {
			EFAB_ERR ( "!\n" );
			continue;
		}

		EFAB_LOG ( "\n%dMbps %s-duplex\n",
			   ( efab->link_options & LPA_EF_10000 ? 10000 :
			     ( efab->link_options & LPA_EF_1000 ? 1000 :
			       ( efab->link_options & LPA_100 ? 100 : 10 ) ) ),
			   ( efab->link_options & LPA_EF_DUPLEX ?
			     "full" : "half" ) );

		/* TODO: Move link state handling to the poll() routine */
		netdev_link_up ( efab->netdev );
		return 0;
	}

	EFAB_ERR ( "timed initialising MAC\n" );
	return -ETIMEDOUT;
}

static void
efab_close ( struct net_device *netdev )
{
	struct efab_nic *efab = netdev_priv ( netdev );

	falcon_fini_resources ( efab );
	efab_free_resources ( efab );
	efab->board_op->fini ( efab );
	falcon_reset ( efab );
}

static int
efab_open ( struct net_device *netdev )
{
	struct efab_nic *efab = netdev_priv ( netdev );
	struct efab_rx_queue *rx_queue = &efab->rx_queue;
	int rc;

	rc = falcon_reset ( efab );
	if ( rc )
		goto fail1;

	rc = efab->board_op->init ( efab );
	if ( rc )
		goto fail2;
	
	rc = falcon_init_sram ( efab );
	if ( rc )
		goto fail3;

	/* Configure descriptor caches before pushing hardware queues */
	falcon_setup_nic ( efab );

	rc = efab_alloc_resources ( efab );
	if ( rc )
		goto fail4;
	
	falcon_init_resources ( efab );

	/* Push rx buffers */
	rc = efab_fill_rx_queue ( efab, rx_queue );
	if ( rc )
		goto fail5;

	/* Try and bring the interface up */
	rc = efab_init_mac ( efab );
	if ( rc )
		goto fail6;

	return 0;

fail6:
fail5:
	efab_free_resources ( efab );
fail4:
fail3:
	efab->board_op->fini ( efab );
fail2:
	falcon_reset ( efab );
fail1:
	return rc;
}

static struct net_device_operations efab_operations = {
        .open           = efab_open,
        .close          = efab_close,
        .transmit       = efab_transmit,
        .poll           = efab_poll,
        .irq            = efab_irq,
};

static void
efab_remove ( struct pci_device *pci )
{
	struct net_device *netdev = pci_get_drvdata ( pci );
	struct efab_nic *efab = netdev_priv ( netdev );

	if ( efab->membase ) {
		falcon_reset ( efab );

		iounmap ( efab->membase );
		efab->membase = NULL;
	}

	if ( efab->nvo.nvs ) {
		unregister_nvo ( &efab->nvo );
		efab->nvo.nvs = NULL;
	}

	unregister_netdev ( netdev );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

static int
efab_probe ( struct pci_device *pci )
{
	struct net_device *netdev;
	struct efab_nic *efab;
	unsigned long mmio_start, mmio_len;
	int rc;

	/* Create the network adapter */
	netdev = alloc_etherdev ( sizeof ( struct efab_nic ) );
	if ( ! netdev ) {
		rc = -ENOMEM;
		goto fail1;
	}

	/* Initialise the network adapter, and initialise private storage */
	netdev_init ( netdev, &efab_operations );
	pci_set_drvdata ( pci, netdev );
	netdev->dev = &pci->dev;

	efab = netdev_priv ( netdev );
	memset ( efab, 0, sizeof ( *efab ) );
	efab->netdev = netdev;

	/* Get iobase/membase */
	mmio_start = pci_bar_start ( pci, PCI_BASE_ADDRESS_2 );
	mmio_len = pci_bar_size ( pci, PCI_BASE_ADDRESS_2 );
	efab->membase = ioremap ( mmio_start, mmio_len );
	EFAB_TRACE ( "BAR of %lx bytes at phys %lx mapped at %p\n",
		     mmio_len, mmio_start, efab->membase );

	/* Enable the PCI device */
	adjust_pci_device ( pci );
	efab->iobase = pci->ioaddr & ~3;

	/* Determine the NIC variant */
	falcon_probe_nic_variant ( efab, pci );

	/* Read the SPI interface and determine the MAC address,
	 * and the board and phy variant. Hook in the op tables */
	rc = falcon_probe_spi ( efab );
	if ( rc )
		goto fail2;
	rc = falcon_probe_nvram ( efab );
	if ( rc )
		goto fail3;

	memcpy ( netdev->hw_addr, efab->mac_addr, ETH_ALEN );

	rc = register_netdev ( netdev );
	if ( rc )
		goto fail4;
	netdev_link_up ( netdev );

	/* Advertise non-volatile storage */
	if ( efab->nvo.nvs ) {
		rc = register_nvo ( &efab->nvo, netdev_settings ( netdev ) );
		if ( rc )
			goto fail5;
	}

	EFAB_LOG ( "Found %s EtherFabric %s %s revision %d\n", pci->id->name,
		   efab->is_asic ? "ASIC" : "FPGA",
		   efab->phy_10g ? "10G" : "1G",
		   efab->pci_revision );

	return 0;

fail5:
	unregister_netdev ( netdev );
fail4:
fail3:
fail2:
	iounmap ( efab->membase );
	efab->membase = NULL;
	netdev_put ( netdev );
fail1:
	return rc;
}


static struct pci_device_id efab_nics[] = {
	PCI_ROM(0x1924, 0x0703, "falcon", "EtherFabric Falcon", 0),
	PCI_ROM(0x1924, 0x0710, "falconb0", "EtherFabric FalconB0", 0),
};

struct pci_driver etherfabric_driver __pci_driver = {
	.ids = efab_nics,
	.id_count = sizeof ( efab_nics ) / sizeof ( efab_nics[0] ),
	.probe = efab_probe,
	.remove = efab_remove,
};

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
