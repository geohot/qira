#ifdef ALLMULTI
#error multicast support is not yet implemented
#endif
 /*------------------------------------------------------------------------
 * smc9000.c
 * This is a Etherboot driver for SMC's 9000 series of Ethernet cards.
 *
 * Copyright (C) 1998 Daniel Engström <daniel.engstrom@riksnett.no>
 * Based on the Linux SMC9000 driver, smc9194.c by Eric Stahlman
 * Copyright (C) 1996 by Erik Stahlman <eric@vt.edu>
 *
 * This software may be used and distributed according to the terms
 * of the GNU Public License, incorporated herein by reference.
 *
 * "Features" of the SMC chip:
 *   4608 byte packet memory. ( for the 91C92/4.  Others have more )
 *   EEPROM for configuration
 *   AUI/TP selection
 *
 * Authors
 *	Erik Stahlman				<erik@vt.edu>
 *      Daniel Engström                         <daniel.engstrom@riksnett.no>
 *
 * History
 * 98-09-25              Daniel Engström Etherboot driver crated from Eric's
 *                                       Linux driver.
 *
 *---------------------------------------------------------------------------*/

FILE_LICENCE ( GPL_ANY );

#define LINUX_OUT_MACROS 1
#define SMC9000_DEBUG    0

#if SMC9000_DEBUG > 1
#define PRINTK2 printf
#else
#define PRINTK2(args...)
#endif

#include <ipxe/ethernet.h>
#include <errno.h>
#include "etherboot.h"
#include "nic.h"
#include <ipxe/isa.h>
#include "smc9000.h"

# define _outb outb
# define _outw outw

static const char       smc9000_version[] = "Version 0.99 98-09-30";
static const char       *interfaces[ 2 ] = { "TP", "AUI" };
static const char       *chip_ids[ 15 ] =  {
   NULL, NULL, NULL,
   /* 3 */ "SMC91C90/91C92",
   /* 4 */ "SMC91C94",
   /* 5 */ "SMC91C95",
   NULL,
   /* 7 */ "SMC91C100",
   /* 8 */ "SMC91C100FD",
   /* 9 */ "SMC91C11xFD",
   NULL, NULL,
   NULL, NULL, NULL
};
static const char      smc91c96_id[] = "SMC91C96";

/*------------------------------------------------------------
 . Reads a register from the MII Management serial interface
 .-------------------------------------------------------------*/
static word smc_read_phy_register(int ioaddr, byte phyaddr, byte phyreg)
{
    int oldBank;
    unsigned int i;
    byte mask;
    word mii_reg;
    byte bits[64];
    int clk_idx = 0;
    int input_idx;
    word phydata;

    // 32 consecutive ones on MDO to establish sync
    for (i = 0; i < 32; ++i)
        bits[clk_idx++] = MII_MDOE | MII_MDO;

    // Start code <01>
    bits[clk_idx++] = MII_MDOE;
    bits[clk_idx++] = MII_MDOE | MII_MDO;

    // Read command <10>
    bits[clk_idx++] = MII_MDOE | MII_MDO;
    bits[clk_idx++] = MII_MDOE;

    // Output the PHY address, msb first
    mask = (byte)0x10;
    for (i = 0; i < 5; ++i)
    {
        if (phyaddr & mask)
            bits[clk_idx++] = MII_MDOE | MII_MDO;
        else
            bits[clk_idx++] = MII_MDOE;

        // Shift to next lowest bit
        mask >>= 1;
    }

    // Output the phy register number, msb first
    mask = (byte)0x10;
    for (i = 0; i < 5; ++i)
    {
        if (phyreg & mask)
            bits[clk_idx++] = MII_MDOE | MII_MDO;
        else
            bits[clk_idx++] = MII_MDOE;

        // Shift to next lowest bit
        mask >>= 1;
    }

    // Tristate and turnaround (2 bit times)
    bits[clk_idx++] = 0;
    //bits[clk_idx++] = 0;

    // Input starts at this bit time
    input_idx = clk_idx;

    // Will input 16 bits
    for (i = 0; i < 16; ++i)
        bits[clk_idx++] = 0;

    // Final clock bit
    bits[clk_idx++] = 0;

    // Save the current bank
    oldBank = inw( ioaddr+BANK_SELECT );

    // Select bank 3
    SMC_SELECT_BANK(ioaddr, 3);

    // Get the current MII register value
    mii_reg = inw( ioaddr+MII_REG );

    // Turn off all MII Interface bits
    mii_reg &= ~(MII_MDOE|MII_MCLK|MII_MDI|MII_MDO);

    // Clock all 64 cycles
    for (i = 0; i < sizeof(bits); ++i)
    {
        // Clock Low - output data
        outw( mii_reg | bits[i], ioaddr+MII_REG );
        udelay(50);


        // Clock Hi - input data
        outw( mii_reg | bits[i] | MII_MCLK, ioaddr+MII_REG );
        udelay(50);
        bits[i] |= inw( ioaddr+MII_REG ) & MII_MDI;
    }

    // Return to idle state
    // Set clock to low, data to low, and output tristated
    outw( mii_reg, ioaddr+MII_REG );
    udelay(50);

    // Restore original bank select
    SMC_SELECT_BANK(ioaddr, oldBank);

    // Recover input data
    phydata = 0;
    for (i = 0; i < 16; ++i)
    {
        phydata <<= 1;

        if (bits[input_idx++] & MII_MDI)
            phydata |= 0x0001;
    }

#if (SMC_DEBUG > 2 )
        printf("smc_read_phy_register(): phyaddr=%x,phyreg=%x,phydata=%x\n",
               phyaddr, phyreg, phydata);
#endif

        return(phydata);
}


/*------------------------------------------------------------
 . Writes a register to the MII Management serial interface
 .-------------------------------------------------------------*/
static void smc_write_phy_register(int ioaddr,
                                   byte phyaddr, byte phyreg, word phydata)
{
    int oldBank;
    unsigned int i;
    word mask;
    word mii_reg;
    byte bits[65];
    int clk_idx = 0;

    // 32 consecutive ones on MDO to establish sync
    for (i = 0; i < 32; ++i)
        bits[clk_idx++] = MII_MDOE | MII_MDO;

    // Start code <01>
    bits[clk_idx++] = MII_MDOE;
    bits[clk_idx++] = MII_MDOE | MII_MDO;

    // Write command <01>
    bits[clk_idx++] = MII_MDOE;
    bits[clk_idx++] = MII_MDOE | MII_MDO;

    // Output the PHY address, msb first
    mask = (byte)0x10;
    for (i = 0; i < 5; ++i)
    {
        if (phyaddr & mask)
            bits[clk_idx++] = MII_MDOE | MII_MDO;
        else
            bits[clk_idx++] = MII_MDOE;

                // Shift to next lowest bit
        mask >>= 1;
    }

    // Output the phy register number, msb first
    mask = (byte)0x10;
    for (i = 0; i < 5; ++i)
    {
        if (phyreg & mask)
            bits[clk_idx++] = MII_MDOE | MII_MDO;
        else
            bits[clk_idx++] = MII_MDOE;

        // Shift to next lowest bit
        mask >>= 1;
    }

    // Tristate and turnaround (2 bit times)
    bits[clk_idx++] = 0;
    bits[clk_idx++] = 0;

    // Write out 16 bits of data, msb first
    mask = 0x8000;
    for (i = 0; i < 16; ++i)
    {
        if (phydata & mask)
            bits[clk_idx++] = MII_MDOE | MII_MDO;
        else
            bits[clk_idx++] = MII_MDOE;

        // Shift to next lowest bit
        mask >>= 1;
    }

    // Final clock bit (tristate)
    bits[clk_idx++] = 0;

    // Save the current bank
    oldBank = inw( ioaddr+BANK_SELECT );

    // Select bank 3
    SMC_SELECT_BANK(ioaddr, 3);

    // Get the current MII register value
    mii_reg = inw( ioaddr+MII_REG );

    // Turn off all MII Interface bits
    mii_reg &= ~(MII_MDOE|MII_MCLK|MII_MDI|MII_MDO);

    // Clock all cycles
    for (i = 0; i < sizeof(bits); ++i)
    {
        // Clock Low - output data
        outw( mii_reg | bits[i], ioaddr+MII_REG );
        udelay(50);


        // Clock Hi - input data
        outw( mii_reg | bits[i] | MII_MCLK, ioaddr+MII_REG );
        udelay(50);
        bits[i] |= inw( ioaddr+MII_REG ) & MII_MDI;
    }

    // Return to idle state
    // Set clock to low, data to low, and output tristated
    outw( mii_reg, ioaddr+MII_REG );
    udelay(50);

    // Restore original bank select
    SMC_SELECT_BANK(ioaddr, oldBank);

#if (SMC_DEBUG > 2 )
        printf("smc_write_phy_register(): phyaddr=%x,phyreg=%x,phydata=%x\n",
               phyaddr, phyreg, phydata);
#endif
}


/*------------------------------------------------------------
 . Finds and reports the PHY address
 .-------------------------------------------------------------*/
static int smc_detect_phy(int ioaddr, byte *pphyaddr)
{
    word phy_id1;
    word phy_id2;
    int phyaddr;
    int found = 0;

    // Scan all 32 PHY addresses if necessary
    for (phyaddr = 0; phyaddr < 32; ++phyaddr)
    {
        // Read the PHY identifiers
        phy_id1  = smc_read_phy_register(ioaddr, phyaddr, PHY_ID1_REG);
        phy_id2  = smc_read_phy_register(ioaddr, phyaddr, PHY_ID2_REG);

        // Make sure it is a valid identifier
        if ((phy_id2 > 0x0000) && (phy_id2 < 0xffff) &&
             (phy_id1 > 0x0000) && (phy_id1 < 0xffff))
        {
            if ((phy_id1 != 0x8000) && (phy_id2 != 0x8000))
            {
                // Save the PHY's address
                *pphyaddr = phyaddr;
                found = 1;
                break;
            }
        }
    }

    if (!found)
    {
        printf("No PHY found\n");
        return(0);
    }

    // Set the PHY type
    if ( (phy_id1 == 0x0016) && ((phy_id2 & 0xFFF0) == 0xF840 ) )
    {
        printf("PHY=LAN83C183 (LAN91C111 Internal)\n");
    }

    if ( (phy_id1 == 0x0282) && ((phy_id2 & 0xFFF0) == 0x1C50) )
    {
        printf("PHY=LAN83C180\n");
    }

    return(1);
}

/*------------------------------------------------------------
 . Configures the specified PHY using Autonegotiation. Calls
 . smc_phy_fixed() if the user has requested a certain config.
 .-------------------------------------------------------------*/
static void smc_phy_configure(int ioaddr)
{
    int timeout;
    byte phyaddr;
    word my_phy_caps; // My PHY capabilities
    word my_ad_caps; // My Advertised capabilities
    word status;
    int rpc_cur_mode = RPC_DEFAULT;
    int lastPhy18;

    // Find the address and type of our phy
    if (!smc_detect_phy(ioaddr, &phyaddr))
    {
        return;
    }

    // Reset the PHY, setting all other bits to zero
    smc_write_phy_register(ioaddr, phyaddr, PHY_CNTL_REG, PHY_CNTL_RST);

    // Wait for the reset to complete, or time out
    timeout = 6; // Wait up to 3 seconds
    while (timeout--)
    {
        if (!(smc_read_phy_register(ioaddr, phyaddr, PHY_CNTL_REG)
              & PHY_CNTL_RST))
        {
            // reset complete
            break;
        }

        mdelay(500); // wait 500 millisecs
    }

    if (timeout < 1)
    {
        PRINTK2("PHY reset timed out\n");
        return;
    }

    // Read PHY Register 18, Status Output
    lastPhy18 = smc_read_phy_register(ioaddr, phyaddr, PHY_INT_REG);

    // Enable PHY Interrupts (for register 18)
    // Interrupts listed here are disabled
    smc_write_phy_register(ioaddr, phyaddr, PHY_MASK_REG,
                           PHY_INT_LOSSSYNC | PHY_INT_CWRD | PHY_INT_SSD |
                                   PHY_INT_ESD | PHY_INT_RPOL | PHY_INT_JAB |
                                   PHY_INT_SPDDET | PHY_INT_DPLXDET);

    /* Configure the Receive/Phy Control register */
    SMC_SELECT_BANK(ioaddr, 0);
    outw( rpc_cur_mode, ioaddr + RPC_REG );

    // Copy our capabilities from PHY_STAT_REG to PHY_AD_REG
    my_phy_caps = smc_read_phy_register(ioaddr, phyaddr, PHY_STAT_REG);
    my_ad_caps  = PHY_AD_CSMA; // I am CSMA capable

    if (my_phy_caps & PHY_STAT_CAP_T4)
        my_ad_caps |= PHY_AD_T4;

    if (my_phy_caps & PHY_STAT_CAP_TXF)
        my_ad_caps |= PHY_AD_TX_FDX;

    if (my_phy_caps & PHY_STAT_CAP_TXH)
        my_ad_caps |= PHY_AD_TX_HDX;

    if (my_phy_caps & PHY_STAT_CAP_TF)
        my_ad_caps |= PHY_AD_10_FDX;

    if (my_phy_caps & PHY_STAT_CAP_TH)
        my_ad_caps |= PHY_AD_10_HDX;

    // Update our Auto-Neg Advertisement Register
    smc_write_phy_register(ioaddr, phyaddr, PHY_AD_REG, my_ad_caps);

    PRINTK2("phy caps=%x\n", my_phy_caps);
    PRINTK2("phy advertised caps=%x\n", my_ad_caps);

    // Restart auto-negotiation process in order to advertise my caps
    smc_write_phy_register( ioaddr, phyaddr, PHY_CNTL_REG,
                            PHY_CNTL_ANEG_EN | PHY_CNTL_ANEG_RST );

    // Wait for the auto-negotiation to complete.  This may take from
    // 2 to 3 seconds.
    // Wait for the reset to complete, or time out
    timeout = 20; // Wait up to 10 seconds
    while (timeout--)
    {
        status = smc_read_phy_register(ioaddr, phyaddr, PHY_STAT_REG);
        if (status & PHY_STAT_ANEG_ACK)
        {
            // auto-negotiate complete
            break;
        }

        mdelay(500); // wait 500 millisecs

        // Restart auto-negotiation if remote fault
        if (status & PHY_STAT_REM_FLT)
        {
            PRINTK2("PHY remote fault detected\n");

            // Restart auto-negotiation
            PRINTK2("PHY restarting auto-negotiation\n");
            smc_write_phy_register( ioaddr, phyaddr, PHY_CNTL_REG,
                                    PHY_CNTL_ANEG_EN | PHY_CNTL_ANEG_RST |
                                    PHY_CNTL_SPEED | PHY_CNTL_DPLX);
        }
    }

    if (timeout < 1)
    {
        PRINTK2("PHY auto-negotiate timed out\n");
    }

    // Fail if we detected an auto-negotiate remote fault
    if (status & PHY_STAT_REM_FLT)
    {
        PRINTK2("PHY remote fault detected\n");
    }

    // Set our sysctl parameters to match auto-negotiation results
    if ( lastPhy18 & PHY_INT_SPDDET )
    {
        PRINTK2("PHY 100BaseT\n");
        rpc_cur_mode |= RPC_SPEED;
    }
    else
    {
        PRINTK2("PHY 10BaseT\n");
        rpc_cur_mode &= ~RPC_SPEED;
    }

    if ( lastPhy18 & PHY_INT_DPLXDET )
    {
        PRINTK2("PHY Full Duplex\n");
        rpc_cur_mode |= RPC_DPLX;
    }
    else
    {
        PRINTK2("PHY Half Duplex\n");
        rpc_cur_mode &= ~RPC_DPLX;
    }

    // Re-Configure the Receive/Phy Control register
    outw( rpc_cur_mode, ioaddr + RPC_REG );
}

/*
 * Function: smc_reset( int ioaddr )
 * Purpose:
 *	This sets the SMC91xx chip to its normal state, hopefully from whatever
 *	mess that any other DOS driver has put it in.
 *
 * Maybe I should reset more registers to defaults in here?  SOFTRESET  should
 * do that for me.
 *
 * Method:
 *	1.  send a SOFT RESET
 *	2.  wait for it to finish
 *	3.  reset the memory management unit
 *      4.  clear all interrupts
 *
*/
static void smc_reset(int ioaddr)
{
   /* This resets the registers mostly to defaults, but doesn't
    * affect EEPROM.  That seems unnecessary */
   SMC_SELECT_BANK(ioaddr, 0);
   _outw( RCR_SOFTRESET, ioaddr + RCR );

   /* this should pause enough for the chip to be happy */
   SMC_DELAY(ioaddr);

   /* Set the transmit and receive configuration registers to
    * default values */
   _outw(RCR_CLEAR, ioaddr + RCR);
   _outw(TCR_CLEAR, ioaddr + TCR);

   /* Reset the MMU */
   SMC_SELECT_BANK(ioaddr, 2);
   _outw( MC_RESET, ioaddr + MMU_CMD );

   /* Note:  It doesn't seem that waiting for the MMU busy is needed here,
    * but this is a place where future chipsets _COULD_ break.  Be wary
    * of issuing another MMU command right after this */
   _outb(0, ioaddr + INT_MASK);
}


/*----------------------------------------------------------------------
 * Function: smc9000_probe_addr( int ioaddr )
 *
 * Purpose:
 *	Tests to see if a given ioaddr points to an SMC9xxx chip.
 *	Returns a 1 on success
 *
 * Algorithm:
 *	(1) see if the high byte of BANK_SELECT is 0x33
 *	(2) compare the ioaddr with the base register's address
 *	(3) see if I recognize the chip ID in the appropriate register
 *
 * ---------------------------------------------------------------------
 */
static int smc9000_probe_addr( isa_probe_addr_t ioaddr )
{
   word bank;
   word	revision_register;
   word base_address_register;

   /* First, see if the high byte is 0x33 */
   bank = inw(ioaddr + BANK_SELECT);
   if ((bank & 0xFF00) != 0x3300) {
      return 0;
   }
   /* The above MIGHT indicate a device, but I need to write to further
    *	test this.  */
   _outw(0x0, ioaddr + BANK_SELECT);
   bank = inw(ioaddr + BANK_SELECT);
   if ((bank & 0xFF00) != 0x3300) {
      return 0;
   }

   /* well, we've already written once, so hopefully another time won't
    *  hurt.  This time, I need to switch the bank register to bank 1,
    *  so I can access the base address register */
   SMC_SELECT_BANK(ioaddr, 1);
   base_address_register = inw(ioaddr + BASE);

   if (ioaddr != (base_address_register >> 3 & 0x3E0))  {
      DBG("SMC9000: IOADDR %hX doesn't match configuration (%hX)."
	  "Probably not a SMC chip\n",
	  ioaddr, base_address_register >> 3 & 0x3E0);
      /* well, the base address register didn't match.  Must not have
       * been a SMC chip after all. */
      return 0;
   }


   /* check if the revision register is something that I recognize.
    * These might need to be added to later, as future revisions
    * could be added.  */
   SMC_SELECT_BANK(ioaddr, 3);
   revision_register  = inw(ioaddr + REVISION);
   if (!chip_ids[(revision_register >> 4) & 0xF]) {
      /* I don't recognize this chip, so... */
      DBG( "SMC9000: IO %hX: Unrecognized revision register:"
	   " %hX, Contact author.\n", ioaddr, revision_register );
      return 0;
   }

   /* at this point I'll assume that the chip is an SMC9xxx.
    * It might be prudent to check a listing of MAC addresses
    * against the hardware address, or do some other tests. */
   return 1;
}


/**************************************************************************
 * ETH_TRANSMIT - Transmit a frame
 ***************************************************************************/
static void smc9000_transmit(
	struct nic *nic,
	const char *d,			/* Destination */
	unsigned int t,			/* Type */
	unsigned int s,			/* size */
	const char *p)			/* Packet */
{
   word length; /* real, length incl. header */
   word numPages;
   unsigned long time_out;
   byte	packet_no;
   word status;
   int i;

   /* We dont pad here since we can have the hardware doing it for us */
   length = (s + ETH_HLEN + 1)&~1;

   /* convert to MMU pages */
   numPages = length / 256;

   if (numPages > 7 ) {
      DBG("SMC9000: Far too big packet error. \n");
      return;
   }

   /* dont try more than, say 30 times */
   for (i=0;i<30;i++) {
      /* now, try to allocate the memory */
      SMC_SELECT_BANK(nic->ioaddr, 2);
      _outw(MC_ALLOC | numPages, nic->ioaddr + MMU_CMD);

      status = 0;
      /* wait for the memory allocation to finnish */
      for (time_out = currticks() + 5*TICKS_PER_SEC; currticks() < time_out; ) {
	 status = inb(nic->ioaddr + INTERRUPT);
	 if ( status & IM_ALLOC_INT ) {
	    /* acknowledge the interrupt */
	    _outb(IM_ALLOC_INT, nic->ioaddr + INTERRUPT);
	    break;
	 }
      }

      if ((status & IM_ALLOC_INT) != 0 ) {
	 /* We've got the memory */
	 break;
      } else {
	 printf("SMC9000: Memory allocation timed out, resetting MMU.\n");
	 _outw(MC_RESET, nic->ioaddr + MMU_CMD);
      }
   }

   /* If I get here, I _know_ there is a packet slot waiting for me */
   packet_no = inb(nic->ioaddr + PNR_ARR + 1);
   if (packet_no & 0x80) {
      /* or isn't there?  BAD CHIP! */
      printf("SMC9000: Memory allocation failed. \n");
      return;
   }

   /* we have a packet address, so tell the card to use it */
   _outb(packet_no, nic->ioaddr + PNR_ARR);

   /* point to the beginning of the packet */
   _outw(PTR_AUTOINC, nic->ioaddr + POINTER);

#if	SMC9000_DEBUG > 2
   printf("Trying to xmit packet of length %hX\n", length );
#endif

   /* send the packet length ( +6 for status, length and ctl byte )
    * and the status word ( set to zeros ) */
   _outw(0, nic->ioaddr + DATA_1 );

   /* send the packet length ( +6 for status words, length, and ctl) */
   _outb((length+6) & 0xFF,  nic->ioaddr + DATA_1);
   _outb((length+6) >> 8 ,   nic->ioaddr + DATA_1);

   /* Write the contents of the packet */

   /* The ethernet header first... */
   outsw(nic->ioaddr + DATA_1, d, ETH_ALEN >> 1);
   outsw(nic->ioaddr + DATA_1, nic->node_addr, ETH_ALEN >> 1);
   _outw(htons(t), nic->ioaddr + DATA_1);

   /* ... the data ... */
   outsw(nic->ioaddr + DATA_1 , p, s >> 1);

   /* ... and the last byte, if there is one.   */
   if ((s & 1) == 0) {
      _outw(0, nic->ioaddr + DATA_1);
   } else {
      _outb(p[s-1], nic->ioaddr + DATA_1);
      _outb(0x20, nic->ioaddr + DATA_1);
   }

   /* and let the chipset deal with it */
   _outw(MC_ENQUEUE , nic->ioaddr + MMU_CMD);

   status = 0; time_out = currticks() + 5*TICKS_PER_SEC;
   do {
      status = inb(nic->ioaddr + INTERRUPT);

      if ((status & IM_TX_INT ) != 0) {
	 word tx_status;

	 /* ack interrupt */
	 _outb(IM_TX_INT, nic->ioaddr + INTERRUPT);

	 packet_no = inw(nic->ioaddr + FIFO_PORTS);
	 packet_no &= 0x7F;

	 /* select this as the packet to read from */
	 _outb( packet_no, nic->ioaddr + PNR_ARR );

	 /* read the first word from this packet */
	 _outw( PTR_AUTOINC | PTR_READ, nic->ioaddr + POINTER );

	 tx_status = inw( nic->ioaddr + DATA_1 );

	 if (0 == (tx_status & TS_SUCCESS)) {
	    DBG("SMC9000: TX FAIL STATUS: %hX \n", tx_status);
	    /* re-enable transmit */
	    SMC_SELECT_BANK(nic->ioaddr, 0);
	    _outw(inw(nic->ioaddr + TCR ) | TCR_ENABLE, nic->ioaddr + TCR );
	 }

	 /* kill the packet */
	 SMC_SELECT_BANK(nic->ioaddr, 2);
	 _outw(MC_FREEPKT, nic->ioaddr + MMU_CMD);

	 return;
      }
   }while(currticks() < time_out);

   printf("SMC9000: TX timed out, resetting board\n");
   smc_reset(nic->ioaddr);
   return;
}

/**************************************************************************
 * ETH_POLL - Wait for a frame
 ***************************************************************************/
static int smc9000_poll(struct nic *nic, int retrieve)
{
   SMC_SELECT_BANK(nic->ioaddr, 2);
   if (inw(nic->ioaddr + FIFO_PORTS) & FP_RXEMPTY)
     return 0;
   
   if ( ! retrieve ) return 1;

   /*  start reading from the start of the packet */
   _outw(PTR_READ | PTR_RCV | PTR_AUTOINC, nic->ioaddr + POINTER);

   /* First read the status and check that we're ok */
   if (!(inw(nic->ioaddr + DATA_1) & RS_ERRORS)) {
      /* Next: read the packet length and mask off the top bits */
      nic->packetlen = (inw(nic->ioaddr + DATA_1) & 0x07ff);

      /* the packet length includes the 3 extra words */
      nic->packetlen -= 6;
#if	SMC9000_DEBUG > 2
      printf(" Reading %d words (and %d byte(s))\n",
	       (nic->packetlen >> 1), nic->packetlen & 1);
#endif
      /* read the packet (and the last "extra" word) */
      insw(nic->ioaddr + DATA_1, nic->packet, (nic->packetlen+2) >> 1);
      /* is there an odd last byte ? */
      if (nic->packet[nic->packetlen+1] & 0x20)
	 nic->packetlen++;

      /*  error or good, tell the card to get rid of this packet */
      _outw(MC_RELEASE, nic->ioaddr + MMU_CMD);
      return 1;
   }

   printf("SMC9000: RX error\n");
   /*  error or good, tell the card to get rid of this packet */
   _outw(MC_RELEASE, nic->ioaddr + MMU_CMD);
   return 0;
}

static void smc9000_disable ( struct nic *nic, struct isa_device *isa __unused ) {

   smc_reset(nic->ioaddr);

   /* no more interrupts for me */
   SMC_SELECT_BANK(nic->ioaddr, 2);
   _outb( 0, nic->ioaddr + INT_MASK);

   /* and tell the card to stay away from that nasty outside world */
   SMC_SELECT_BANK(nic->ioaddr, 0);
   _outb( RCR_CLEAR, nic->ioaddr + RCR );
   _outb( TCR_CLEAR, nic->ioaddr + TCR );
}

static void smc9000_irq(struct nic *nic __unused, irq_action_t action __unused)
{
  switch ( action ) {
  case DISABLE :
    break;
  case ENABLE :
    break;
  case FORCE :
    break;
  }
}

static struct nic_operations smc9000_operations = {
	.connect	= dummy_connect,
	.poll		= smc9000_poll,
	.transmit	= smc9000_transmit,
	.irq		= smc9000_irq,

};

/**************************************************************************
 * ETH_PROBE - Look for an adapter
 ***************************************************************************/

static int smc9000_probe ( struct nic *nic, struct isa_device *isa ) {

   unsigned short   revision;
   int	            memory;
   int              media;
   const char *	    version_string;
   const char *	    if_string;
   int              i;

   nic->irqno  = 0;
   nic->ioaddr = isa->ioaddr;

   /*
    * Get the MAC address ( bank 1, regs 4 - 9 )
    */
   SMC_SELECT_BANK(nic->ioaddr, 1);
   for ( i = 0; i < 6; i += 2 ) {
      word address;

      address = inw(nic->ioaddr + ADDR0 + i);
      nic->node_addr[i+1] = address >> 8;
      nic->node_addr[i] = address & 0xFF;
   }

   /* get the memory information */
   SMC_SELECT_BANK(nic->ioaddr, 0);
   memory = ( inw(nic->ioaddr + MCR) >> 9 )  & 0x7;  /* multiplier */
   memory *= 256 * (inw(nic->ioaddr + MIR) & 0xFF);

   /*
    * Now, I want to find out more about the chip.  This is sort of
    * redundant, but it's cleaner to have it in both, rather than having
    * one VERY long probe procedure.
    */
   SMC_SELECT_BANK(nic->ioaddr, 3);
   revision  = inw(nic->ioaddr + REVISION);
   version_string = chip_ids[(revision >> 4) & 0xF];

   if (((revision & 0xF0) >> 4 == CHIP_9196) &&
       ((revision & 0x0F) >= REV_9196)) {
      /* This is a 91c96. 'c96 has the same chip id as 'c94 (4) but
       * a revision starting at 6 */
      version_string = smc91c96_id;
   }

   if ( !version_string ) {
      /* I shouldn't get here because this call was done before.... */
      return 0;
   }

   /* is it using AUI or 10BaseT ? */
   SMC_SELECT_BANK(nic->ioaddr, 1);
   if (inw(nic->ioaddr + CFG) & CFG_AUI_SELECT)
     media = 2;
   else
     media = 1;

   if_string = interfaces[media - 1];

   /* now, reset the chip, and put it into a known state */
   smc_reset(nic->ioaddr);

   printf("SMC9000 %s\n", smc9000_version);
   DBG("Copyright (C) 1998 Daniel Engstr\x94m\n");
   DBG("Copyright (C) 1996 Eric Stahlman\n");

   printf("%s rev:%d I/O port:%hX Interface:%s RAM:%d bytes \n",
	  version_string, revision & 0xF,
	  nic->ioaddr, if_string, memory );

   DBG ( "Ethernet MAC address: %s\n", eth_ntoa ( nic->node_addr ) );

   SMC_SELECT_BANK(nic->ioaddr, 0);

   /* see the header file for options in TCR/RCR NORMAL*/
   _outw(TCR_NORMAL, nic->ioaddr + TCR);
   _outw(RCR_NORMAL, nic->ioaddr + RCR);

   /* Select which interface to use */
   SMC_SELECT_BANK(nic->ioaddr, 1);
   if ( media == 1 ) {
      _outw( inw( nic->ioaddr + CFG ) & ~CFG_AUI_SELECT,
	   nic->ioaddr + CFG );
   }
   else if ( media == 2 ) {
      _outw( inw( nic->ioaddr + CFG ) | CFG_AUI_SELECT,
	   nic->ioaddr + CFG );
   }

   smc_phy_configure(nic->ioaddr);
 
   nic->nic_op	= &smc9000_operations;
   return 1;
}

/*
 * The SMC9000 can be at any of the following port addresses.  To
 * change for a slightly different card, you can add it to the array.
 *
 */
static isa_probe_addr_t smc9000_probe_addrs[] = {
   0x200, 0x220, 0x240, 0x260, 0x280, 0x2A0, 0x2C0, 0x2E0,
   0x300, 0x320, 0x340, 0x360, 0x380, 0x3A0, 0x3C0, 0x3E0,
};

ISA_DRIVER ( smc9000_driver, smc9000_probe_addrs, smc9000_probe_addr,
		     GENERIC_ISAPNP_VENDOR, 0x8228 );

DRIVER ( "SMC9000", nic_driver, isa_driver, smc9000_driver,
	 smc9000_probe, smc9000_disable );

ISA_ROM ( "smc9000", "SMC9000" );

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
