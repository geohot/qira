/*
 * 3c90x.c -- This file implements a iPXE API 3c90x driver
 *
 * Originally written for etherboot by:
 *   Greg Beeley, Greg.Beeley@LightSys.org
 * Modified by Steve Smith,
 *   Steve.Smith@Juno.Com. Alignment bug fix Neil Newell (nn@icenoir.net).
 * Almost totally Rewritten to use iPXE API, implementation of tx/rx ring support
 *   by Thomas Miletich, thomas.miletich@gmail.com
 *   Thanks to Marty Connor and Stefan Hajnoczi for their help and feedback,
 *   and to Daniel Verkamp for his help with testing.
 *
 * Copyright (c) 2009 Thomas Miletich
 *
 * Copyright (c) 1999 LightSys Technology Services, Inc.
 * Portions Copyright (c) 1999 Steve Smith
 *
 * This program may be re-distributed in source or binary form, modified,
 * sold, or copied for any purpose, provided that the above copyright message
 * and this text are included with all source copies or derivative works, and
 * provided that the above copyright message and this text are included in the
 * documentation of any binary-only distributions.  This program is distributed
 * WITHOUT ANY WARRANTY, without even the warranty of FITNESS FOR A PARTICULAR
 * PURPOSE or MERCHANTABILITY.  Please read the associated documentation
 * "3c90x.txt" before compiling and using this driver.
 *
 * [ --mdc 20090313 The 3c90x.txt file is now at:
 *   http://etherboot.org/wiki/appnotes/3c90x_issues ]
 *
 * This program was written with the assistance of the 3com documentation for
 * the 3c905B-TX card, as well as with some assistance from the 3c59x
 * driver Donald Becker wrote for the Linux kernel, and with some assistance
 * from the remainder of the Etherboot distribution.
 *
 * Indented with unix 'indent' command: 
 *   $ indent -kr -i8 3c90x.c
 */

FILE_LICENCE ( BSD2 );

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <byteswap.h>
#include <errno.h>
#include <ipxe/ethernet.h>
#include <ipxe/if_ether.h>
#include <ipxe/io.h>
#include <ipxe/iobuf.h>
#include <ipxe/malloc.h>
#include <ipxe/netdevice.h>
#include <ipxe/pci.h>
#include <ipxe/timer.h>
#include <ipxe/nvs.h>

#include "3c90x.h"

/**
 * a3c90x_internal_IssueCommand: sends a command to the 3c90x card
 * and waits for it's completion
 *
 * @v ioaddr	IOAddress of the NIC
 * @v cmd	Command to be issued
 * @v param	Command parameter
 */
static void a3c90x_internal_IssueCommand(int ioaddr, int cmd, int param)
{
	unsigned int val = (cmd << 11) | param;
	int cnt = 0;

	DBGP("a3c90x_internal_IssueCommand\n");

	/* Send the cmd to the cmd register */
	outw(val, ioaddr + regCommandIntStatus_w);

	/* Wait for the cmd to complete */
	for (cnt = 0; cnt < 100000; cnt++) {
		if (inw(ioaddr + regCommandIntStatus_w) & INT_CMDINPROGRESS) {
			continue;
		} else {
			DBG2("Command 0x%04X finished in time. cnt = %d.\n", cmd, cnt);
			return;
		}
	}

	DBG("Command 0x%04X DID NOT finish in time. cnt = %d.\n", cmd, cnt);
}

/**
 * a3c90x_internal_SetWindow: selects a register window set.
 *
 * @v inf_3c90x	private NIC data
 * @v window	window to be selected
 */
static void a3c90x_internal_SetWindow(struct INF_3C90X *inf_3c90x, int window)
{
	DBGP("a3c90x_internal_SetWindow\n");
	/* Window already as set? */
	if (inf_3c90x->CurrentWindow == window)
		return;

	/* Issue the window command. */
	a3c90x_internal_IssueCommand(inf_3c90x->IOAddr,
				     cmdSelectRegisterWindow, window);
	inf_3c90x->CurrentWindow = window;

	return;
}

static void a3c90x_internal_WaitForEeprom(struct INF_3C90X *inf_3c90x)
{
	int cnt = 0;

	DBGP("a3c90x_internal_WaitForEeprom\n");

	while (eepromBusy & inw(inf_3c90x->IOAddr + regEepromCommand_0_w)) {
		if (cnt == EEPROM_TIMEOUT) {
			DBG("Read from eeprom failed: timeout\n");
			return;
		}
		udelay(1);
		cnt++;
	}
}

/**
 * a3c90x_internal_ReadEeprom - nvs routine to read eeprom data
 * We only support reading one word(2 byte). The nvs subsystem will make sure
 * that the routine will never be called with len != 2.
 *
 * @v nvs	nvs data.
 * @v address	eeprom address to read data from.
 * @v data	data is put here.
 * @v len	number of bytes to read.
 */
static int
a3c90x_internal_ReadEeprom(struct nvs_device *nvs, unsigned int address, void *data, size_t len)
{
	unsigned short *dest = (unsigned short *) data;
	struct INF_3C90X *inf_3c90x =
	    container_of(nvs, struct INF_3C90X, nvs);

	DBGP("a3c90x_internal_ReadEeprom\n");

	/* we support reading 2 bytes only */
	assert(len == 2);

	/* Select correct window */
	a3c90x_internal_SetWindow(inf_3c90x, winEepromBios0);

	/* set eepromRead bits in command sent to NIC */
	address += (inf_3c90x->is3c556 ? eepromRead_556 : eepromRead);

	a3c90x_internal_WaitForEeprom(inf_3c90x);
	/* send address to NIC */
	outw(address, inf_3c90x->IOAddr + regEepromCommand_0_w);
	a3c90x_internal_WaitForEeprom(inf_3c90x);

	/* read value */
	*dest = inw(inf_3c90x->IOAddr + regEepromData_0_w);

	return 0;
}

/**
 * a3c90x_internal_WriteEeprom - nvs routine to write eeprom data
 * currently not implemented
 *
 * @v nvs	nvs data.
 * @v address	eeprom address to read data from.
 * @v data	data is put here.
 * @v len	number of bytes to read.
 */
static int
a3c90x_internal_WriteEeprom(struct nvs_device *nvs __unused,
			    unsigned int address __unused,
			    const void *data __unused, size_t len __unused)
{
	return -ENOTSUP;
}

static void a3c90x_internal_ReadEepromContents(struct INF_3C90X *inf_3c90x)
{
	int eeprom_size = (inf_3c90x->isBrev ? 0x20 : 0x17) * 2;

	DBGP("a3c90x_internal_ReadEepromContents\n");

	nvs_read(&inf_3c90x->nvs, 0, inf_3c90x->eeprom, eeprom_size);
}

/**
 * a3c90x_reset: exported function that resets the card to its default
 * state.  This is so the Linux driver can re-set the card up the way
 * it wants to.  If CFG_3C90X_PRESERVE_XCVR is defined, then the reset will
 * not alter the selected transceiver that we used to download the boot
 * image.
 *
 * @v inf_3c90x	Private NIC data
 */
static void a3c90x_reset(struct INF_3C90X *inf_3c90x)
{
	DBGP("a3c90x_reset\n");
	/* Send the reset command to the card */
	DBG2("3c90x: Issuing RESET\n");

	/* reset of the receiver on B-revision cards re-negotiates the link
	 * takes several seconds (a computer eternity), so we don't reset
	 * it here.
	 */
	a3c90x_internal_IssueCommand(inf_3c90x->IOAddr,
				     cmdGlobalReset,
				     globalResetMaskNetwork);

	/* global reset command resets station mask, non-B revision cards
	 * require explicit reset of values
	 */
	a3c90x_internal_SetWindow(inf_3c90x, winAddressing2);
	outw(0, inf_3c90x->IOAddr + regStationMask_2_3w + 0);
	outw(0, inf_3c90x->IOAddr + regStationMask_2_3w + 2);
	outw(0, inf_3c90x->IOAddr + regStationMask_2_3w + 4);

	a3c90x_internal_IssueCommand(inf_3c90x->IOAddr, cmdTxEnable, 0);
	a3c90x_internal_IssueCommand(inf_3c90x->IOAddr, cmdRxEnable, 0);

	/* enable rxComplete and txComplete indications */
	a3c90x_internal_IssueCommand(inf_3c90x->IOAddr,
				     cmdSetIndicationEnable,
				     INT_TXCOMPLETE | INT_UPCOMPLETE);

	/* acknowledge any pending status flags */
	a3c90x_internal_IssueCommand(inf_3c90x->IOAddr,
				     cmdAcknowledgeInterrupt, 0x661);

	return;
}

/**
 * a3c90x_setup_tx_ring - Allocates TX ring, initialize tx_desc values
 *
 * @v p	Private NIC data
 *
 * @ret Returns 0 on success, negative on failure
 */
static int a3c90x_setup_tx_ring(struct INF_3C90X *p)
{
	DBGP("a3c90x_setup_tx_ring\n");
	p->tx_ring =
	    malloc_dma(TX_RING_SIZE * sizeof(struct TXD), TX_RING_ALIGN);

	if (!p->tx_ring) {
		DBG("Could not allocate TX-ring\n");
		return -ENOMEM;
	}

	memset(p->tx_ring, 0, TX_RING_SIZE * sizeof(struct TXD));
	p->tx_cur = 0;
	p->tx_cnt = 0;
	p->tx_tail = 0;

	return 0;
}

/**
 * a3c90x_process_tx_packets - Checks for successfully sent packets,
 * reports them to iPXE with netdev_tx_complete();
 *
 * @v netdev	Network device info
 */
static void a3c90x_process_tx_packets(struct net_device *netdev)
{
	struct INF_3C90X *p = netdev_priv(netdev);
	unsigned int downlist_ptr;

	DBGP("a3c90x_process_tx_packets\n");

	DBG2("    tx_cnt: %d\n", p->tx_cnt);

	while (p->tx_tail != p->tx_cur) {

		downlist_ptr = inl(p->IOAddr + regDnListPtr_l);

		DBG2("    downlist_ptr: %#08x\n", downlist_ptr);
		DBG2("    tx_tail: %d tx_cur: %d\n", p->tx_tail, p->tx_cur);

		/* NIC is currently working on this tx desc */
		if(downlist_ptr == virt_to_bus(p->tx_ring + p->tx_tail))
			return;

		netdev_tx_complete(netdev, p->tx_iobuf[p->tx_tail]);

		DBG2("transmitted packet\n");
		DBG2("    size: %zd\n", iob_len(p->tx_iobuf[p->tx_tail]));

		p->tx_tail = (p->tx_tail + 1) % TX_RING_SIZE;
		p->tx_cnt--;
	}
}

static void a3c90x_free_tx_ring(struct INF_3C90X *p)
{
	DBGP("a3c90x_free_tx_ring\n");

	free_dma(p->tx_ring, TX_RING_SIZE * sizeof(struct TXD));
	p->tx_ring = NULL;
	/* io_buffers are free()ed by netdev_tx_complete[,_err]() */
}

/**
 * a3c90x_transmit - Transmits a packet.
 *
 * @v netdev	Network device info
 * @v iob		io_buffer containing the data to be send
 *
 * @ret	Returns 0 on success, negative on failure
 */
static int a3c90x_transmit(struct net_device *netdev,
			   struct io_buffer *iob)
{
	struct INF_3C90X *inf_3c90x = netdev_priv(netdev);
	struct TXD *tx_cur_desc;
	struct TXD *tx_prev_desc;

	unsigned int len;
	unsigned int downlist_ptr;

	DBGP("a3c90x_transmit\n");

	if (inf_3c90x->tx_cnt == TX_RING_SIZE) {
		DBG("TX-Ring overflow\n");
		return -ENOBUFS;
	}

	inf_3c90x->tx_iobuf[inf_3c90x->tx_cur] = iob;
	tx_cur_desc = inf_3c90x->tx_ring + inf_3c90x->tx_cur;

	tx_prev_desc = inf_3c90x->tx_ring +
	    (((inf_3c90x->tx_cur + TX_RING_SIZE) - 1) % TX_RING_SIZE);

	len = iob_len(iob);

	/* Setup the DPD (download descriptor) */
	tx_cur_desc->DnNextPtr = 0;

	/* FrameStartHeader differs in 90x and >= 90xB
	 * It contains the packet length in 90x and a round up boundary and
	 * packet ID for 90xB and 90xC. Disable packet length round-up on the
	 * later revisions.
	 */
	tx_cur_desc->FrameStartHeader =
	    fshTxIndicate | (inf_3c90x->isBrev ? fshRndupDefeat : len);

	tx_cur_desc->DataAddr = virt_to_bus(iob->data);
	tx_cur_desc->DataLength = len | downLastFrag;

	/* We have to stall the download engine, so the NIC won't access the
	 * tx descriptor while we modify it. There is a way around this
	 * from revision B and upwards. To stay compatible with older revisions
	 * we don't use it here.
	 */
	a3c90x_internal_IssueCommand(inf_3c90x->IOAddr, cmdStallCtl,
				     dnStall);

	tx_prev_desc->DnNextPtr = virt_to_bus(tx_cur_desc);

	downlist_ptr = inl(inf_3c90x->IOAddr + regDnListPtr_l);
	if (downlist_ptr == 0) {
		/* currently no DownList, sending a new one */
		outl(virt_to_bus(tx_cur_desc),
		     inf_3c90x->IOAddr + regDnListPtr_l);
	}

	/* End Stall */
	a3c90x_internal_IssueCommand(inf_3c90x->IOAddr, cmdStallCtl,
				     dnUnStall);

	inf_3c90x->tx_cur = (inf_3c90x->tx_cur + 1) % TX_RING_SIZE;
	inf_3c90x->tx_cnt++;

	return 0;
}

/**
 * a3c90x_prepare_rx_desc - fills the rx desc with initial data
 *
 * @v p		NIC private data
 * @v index	Index for rx_iobuf and rx_ring array
 */

static void a3c90x_prepare_rx_desc(struct INF_3C90X *p, unsigned int index)
{
	DBGP("a3c90x_prepare_rx_desc\n");
	DBG2("Populating rx_desc %d\n", index);

	/* We have to stall the upload engine, so the NIC won't access the
	 * rx descriptor while we modify it. There is a way around this
	 * from revision B and upwards. To stay compatible with older revisions
	 * we don't use it here.
	 */
	a3c90x_internal_IssueCommand(p->IOAddr, cmdStallCtl, upStall);

	p->rx_ring[index].DataAddr = virt_to_bus(p->rx_iobuf[index]->data);
	p->rx_ring[index].DataLength = RX_BUF_SIZE | upLastFrag;
	p->rx_ring[index].UpPktStatus = 0;

	/* unstall upload engine */
	a3c90x_internal_IssueCommand(p->IOAddr, cmdStallCtl, upUnStall);
}

/**
 * a3c90x_refill_rx_ring -checks every entry in the rx ring and reallocates
 * them as necessary. Then it calls a3c90x_prepare_rx_desc to fill the rx desc
 * with initial data.
 *
 * @v p		NIC private data
 */
static void a3c90x_refill_rx_ring(struct INF_3C90X *p)
{
	int i;
	unsigned int status;
	struct RXD *rx_cur_desc;

	DBGP("a3c90x_refill_rx_ring\n");

	for (i = 0; i < RX_RING_SIZE; i++) {
		rx_cur_desc = p->rx_ring + i;
		status = rx_cur_desc->UpPktStatus;

		/* only refill used descriptor */
		if (!(status & upComplete))
			continue;

		/* we still need to process this descriptor */
		if (p->rx_iobuf[i] != NULL)
			continue;

		p->rx_iobuf[i] = alloc_iob(RX_BUF_SIZE);
		if (p->rx_iobuf[i] == NULL) {
			DBG("alloc_iob() failed\n");
			break;
		}

		a3c90x_prepare_rx_desc(p, i);
	}
}

/**
 * a3c90x_setup_rx_ring - Allocates RX ring, initialize rx_desc values
 *
 * @v p	Private NIC data
 *
 * @ret Returns 0 on success, negative on failure
 */
static int a3c90x_setup_rx_ring(struct INF_3C90X *p)
{
	int i;

	DBGP("a3c90x_setup_rx_ring\n");

	p->rx_ring =
	    malloc_dma(RX_RING_SIZE * sizeof(struct RXD), RX_RING_ALIGN);

	if (!p->rx_ring) {
		DBG("Could not allocate RX-ring\n");
		return -ENOMEM;
	}

	p->rx_cur = 0;

	for (i = 0; i < RX_RING_SIZE; i++) {
		p->rx_ring[i].UpNextPtr =
		    virt_to_bus(p->rx_ring + (i + 1));

		/* these are needed so refill_rx_ring initializes the ring */
		p->rx_ring[i].UpPktStatus = upComplete;
		p->rx_iobuf[i] = NULL;
	}

	/* Loop the ring */
	p->rx_ring[i - 1].UpNextPtr = virt_to_bus(p->rx_ring);

	a3c90x_refill_rx_ring(p);

	return 0;
}

static void a3c90x_free_rx_ring(struct INF_3C90X *p)
{
	DBGP("a3c90x_free_rx_ring\n");

	free_dma(p->rx_ring, RX_RING_SIZE * sizeof(struct RXD));
	p->rx_ring = NULL;
}

static void a3c90x_free_rx_iobuf(struct INF_3C90X *p)
{
	int i;

	DBGP("a3c90x_free_rx_iobuf\n");

	for (i = 0; i < RX_RING_SIZE; i++) {
		free_iob(p->rx_iobuf[i]);
		p->rx_iobuf[i] = NULL;
	}
}

/**
 * a3c90x_process_rx_packets - Checks for received packets,
 * reports them to iPXE with netdev_rx() or netdev_rx_err() if there was an
 * error while receiving the packet
 *
 * @v netdev	Network device info
 */
static void a3c90x_process_rx_packets(struct net_device *netdev)
{
	int i;
	unsigned int rx_status;
	struct INF_3C90X *p = netdev_priv(netdev);
	struct RXD *rx_cur_desc;

	DBGP("a3c90x_process_rx_packets\n");

	for (i = 0; i < RX_RING_SIZE; i++) {
		rx_cur_desc = p->rx_ring + p->rx_cur;
		rx_status = rx_cur_desc->UpPktStatus;

		if (!(rx_status & upComplete) && !(rx_status & upError))
			break;

		if (p->rx_iobuf[p->rx_cur] == NULL)
			break;

		if (rx_status & upError) {
			DBG("Corrupted packet received: %#x\n", rx_status);
			netdev_rx_err(netdev, p->rx_iobuf[p->rx_cur],
				      -EINVAL);
		} else {
			/* if we're here, we've got good packet */
			int packet_len;

			packet_len = rx_status & 0x1FFF;
			iob_put(p->rx_iobuf[p->rx_cur], packet_len);

			DBG2("received packet\n");
			DBG2("    size: %d\n", packet_len);

			netdev_rx(netdev, p->rx_iobuf[p->rx_cur]);
		}

		p->rx_iobuf[p->rx_cur] = NULL;	/* invalidate rx desc */
		p->rx_cur = (p->rx_cur + 1) % RX_RING_SIZE;
	}
	a3c90x_refill_rx_ring(p);

}

/**
 * a3c90x_poll - Routine that gets called periodically.
 * Here we hanle transmitted and received packets.
 * We could also check the link status from time to time, which we
 * currently don't do.
 *
 * @v netdev	Network device info
 */
static void a3c90x_poll(struct net_device *netdev)
{
	struct INF_3C90X *p = netdev_priv(netdev);
	uint16_t raw_status, int_status;

	DBGP("a3c90x_poll\n");

	raw_status = inw(p->IOAddr + regCommandIntStatus_w);
	int_status = (raw_status & 0x0FFF);

	if ( int_status == 0 )
		return;

	a3c90x_internal_IssueCommand(p->IOAddr, cmdAcknowledgeInterrupt,
				     int_status);

	if (int_status & INT_TXCOMPLETE)
		outb(0x00, p->IOAddr + regTxStatus_b);

	DBG2("poll: status = %#04x\n", raw_status);

	a3c90x_process_tx_packets(netdev);

	a3c90x_process_rx_packets(netdev);
}



static void a3c90x_free_resources(struct INF_3C90X *p)
{
	DBGP("a3c90x_free_resources\n");

	a3c90x_free_tx_ring(p);
	a3c90x_free_rx_ring(p);
	a3c90x_free_rx_iobuf(p);
}

/**
 * a3c90x_remove - Routine to remove the card. Unregisters
 * the NIC from iPXE, disables RX/TX and resets the card.
 *
 * @v pci	PCI device info
 */
static void a3c90x_remove(struct pci_device *pci)
{
	struct net_device *netdev = pci_get_drvdata(pci);
	struct INF_3C90X *inf_3c90x = netdev_priv(netdev);

	DBGP("a3c90x_remove\n");

	a3c90x_reset(inf_3c90x);

	/* Disable the receiver and transmitter. */
	outw(cmdRxDisable, inf_3c90x->IOAddr + regCommandIntStatus_w);
	outw(cmdTxDisable, inf_3c90x->IOAddr + regCommandIntStatus_w);

	unregister_netdev(netdev);
	netdev_nullify(netdev);
	netdev_put(netdev);
}

static void a3c90x_irq(struct net_device *netdev, int enable)
{
	struct INF_3C90X *p = netdev_priv(netdev);

	DBGP("a3c90x_irq\n");

	if (enable == 0) {
		/* disable interrupts */
		a3c90x_internal_IssueCommand(p->IOAddr,
					     cmdSetInterruptEnable, 0);
	} else {
		a3c90x_internal_IssueCommand(p->IOAddr,
					     cmdSetInterruptEnable,
					     INT_TXCOMPLETE |
					     INT_UPCOMPLETE);
		a3c90x_internal_IssueCommand(p->IOAddr,
					     cmdAcknowledgeInterrupt,
					     0x661);
	}
}

/**
 * a3c90x_hw_start - Initialize hardware, copy MAC address
 * to NIC registers, set default receiver
 */
static void a3c90x_hw_start(struct net_device *netdev)
{
	int i, c;
	unsigned int cfg;
	unsigned int mopt;
	unsigned short linktype;
	struct INF_3C90X *inf_3c90x = netdev_priv(netdev);

	DBGP("a3c90x_hw_start\n");

	/* 3C556: Invert MII power */
	if (inf_3c90x->is3c556) {
		unsigned int tmp;
		a3c90x_internal_SetWindow(inf_3c90x, winAddressing2);
		tmp = inw(inf_3c90x->IOAddr + regResetOptions_2_w);
		tmp |= 0x4000;
		outw(tmp, inf_3c90x->IOAddr + regResetOptions_2_w);
	}

	/* Copy MAC address into the NIC registers */
	a3c90x_internal_SetWindow(inf_3c90x, winAddressing2);
	for (i = 0; i < ETH_ALEN; i++)
		outb(netdev->ll_addr[i],
		     inf_3c90x->IOAddr + regStationAddress_2_3w + i);
	for (i = 0; i < ETH_ALEN; i++)
		outb(0, inf_3c90x->IOAddr + regStationMask_2_3w + i);

	/* Read the media options register, print a message and set default
	* xcvr.
	*
	* Uses Media Option command on B revision, Reset Option on non-B
	* revision cards -- same register address
	*/
	a3c90x_internal_SetWindow(inf_3c90x, winTxRxOptions3);
	mopt = inw(inf_3c90x->IOAddr + regResetMediaOptions_3_w);

	/* mask out VCO bit that is defined as 10baseFL bit on B-rev cards */
	if (!inf_3c90x->isBrev) {
		mopt &= 0x7F;
	}

	DBG2("Connectors present: ");
	c = 0;
	linktype = 0x0008;
	if (mopt & 0x01) {
		DBG2("%s100Base-T4", (c++) ? ", " : "");
		linktype = linkMII;
	}
	if (mopt & 0x04) {
		DBG2("%s100Base-FX", (c++) ? ", " : "");
		linktype = link100BaseFX;
	}
	if (mopt & 0x10) {
		DBG2("%s10Base-2", (c++) ? ", " : "");
		linktype = link10Base2;
	}
	if (mopt & 0x20) {
		DBG2("%sAUI", (c++) ? ", " : "");
		linktype = linkAUI;
	}
	if (mopt & 0x40) {
		DBG2("%sMII", (c++) ? ", " : "");
		linktype = linkMII;
	}
	if ((mopt & 0xA) == 0xA) {
		DBG2("%s10Base-T / 100Base-TX", (c++) ? ", " : "");
		linktype = linkAutoneg;
	} else if ((mopt & 0xA) == 0x2) {
		DBG2("%s100Base-TX", (c++) ? ", " : "");
		linktype = linkAutoneg;
	} else if ((mopt & 0xA) == 0x8) {
		DBG2("%s10Base-T", (c++) ? ", " : "");
		linktype = linkAutoneg;
	}
	DBG2(".\n");

	/* Determine transceiver type to use, depending on value stored in
	* eeprom 0x16
	*/
	if (inf_3c90x->isBrev) {
		if ((inf_3c90x->eeprom[0x16] & 0xFF00) == XCVR_MAGIC) {
			/* User-defined */
			linktype = inf_3c90x->eeprom[0x16] & 0x000F;
		}
	} else {
		/* I don't know what MII MAC only mode is!!! */
		if (linktype == linkExternalMII) {
			if (inf_3c90x->isBrev)
				DBG("WARNING: MII External MAC Mode only supported on B-revision " "cards!!!!\nFalling Back to MII Mode\n");
			linktype = linkMII;
		}
	}

	/* enable DC converter for 10-Base-T */
	if (linktype == link10Base2) {
		a3c90x_internal_IssueCommand(inf_3c90x->IOAddr,
					     cmdEnableDcConverter, 0);
	}

	/* Set the link to the type we just determined. */
	a3c90x_internal_SetWindow(inf_3c90x, winTxRxOptions3);
	cfg = inl(inf_3c90x->IOAddr + regInternalConfig_3_l);
	cfg &= ~(0xF << 20);
	cfg |= (linktype << 20);

	DBG2("Setting internal cfg register: 0x%08X (linktype: 0x%02X)\n",
	    cfg, linktype);

	outl(cfg, inf_3c90x->IOAddr + regInternalConfig_3_l);

	/* Now that we set the xcvr type, reset the Tx and Rx */
	a3c90x_internal_IssueCommand(inf_3c90x->IOAddr, cmdTxReset, 0x00);

	if (!inf_3c90x->isBrev)
		outb(0x01, inf_3c90x->IOAddr + regTxFreeThresh_b);

	/* Set the RX filter = receive only individual pkts & multicast & bcast. */
	a3c90x_internal_IssueCommand(inf_3c90x->IOAddr, cmdSetRxFilter,
				     0x01 + 0x02 + 0x04);


	/*
	* set Indication and Interrupt flags , acknowledge any IRQ's
	*/
	a3c90x_internal_IssueCommand(inf_3c90x->IOAddr,
				     cmdSetInterruptEnable,
	 INT_TXCOMPLETE | INT_UPCOMPLETE);
	a3c90x_internal_IssueCommand(inf_3c90x->IOAddr,
				     cmdSetIndicationEnable,
	 INT_TXCOMPLETE | INT_UPCOMPLETE);
	a3c90x_internal_IssueCommand(inf_3c90x->IOAddr,
				     cmdAcknowledgeInterrupt, 0x661);
}

/**
 * a3c90x_open - Routine to initialize the card. Initialize hardware,
 * allocate TX and RX ring, send RX ring address to the NIC.
 *
 * @v netdev	Network device info
 *
 * @ret Returns 0 on success, negative on failure
 */
static int a3c90x_open(struct net_device *netdev)
{
	int rc;
	struct INF_3C90X *inf_3c90x = netdev_priv(netdev);

	DBGP("a3c90x_open\n");

	a3c90x_hw_start(netdev);

	rc = a3c90x_setup_tx_ring(inf_3c90x);
	if (rc != 0) {
		DBG("Error setting up TX Ring\n");
		goto error;
	}

	rc = a3c90x_setup_rx_ring(inf_3c90x);
	if (rc != 0) {
		DBG("Error setting up RX Ring\n");
		goto error;
	}

	a3c90x_internal_IssueCommand(inf_3c90x->IOAddr, cmdStallCtl, upStall);

	/* send rx_ring address to NIC */
	outl(virt_to_bus(inf_3c90x->rx_ring),
	     inf_3c90x->IOAddr + regUpListPtr_l);

	a3c90x_internal_IssueCommand(inf_3c90x->IOAddr, cmdStallCtl, upUnStall);

	/* set maximum allowed receive packet length */
	a3c90x_internal_SetWindow(inf_3c90x, winTxRxOptions3);
	outl(RX_BUF_SIZE, inf_3c90x->IOAddr + regMaxPktSize_3_w);

	/* enable packet transmission and reception */
	a3c90x_internal_IssueCommand(inf_3c90x->IOAddr, cmdTxEnable, 0);
	a3c90x_internal_IssueCommand(inf_3c90x->IOAddr, cmdRxEnable, 0);

	return 0;

      error:
	a3c90x_free_resources(inf_3c90x);
	a3c90x_reset(inf_3c90x);
	return rc;
}

/**
 * a3c90x_close - free()s TX and RX ring, disablex RX/TX, resets NIC
 *
 * @v netdev	Network device info
 */
static void a3c90x_close(struct net_device *netdev)
{
	struct INF_3C90X *inf_3c90x = netdev_priv(netdev);

	DBGP("a3c90x_close\n");

	a3c90x_reset(inf_3c90x);
	outw(cmdRxDisable, inf_3c90x->IOAddr + regCommandIntStatus_w);
	outw(cmdTxDisable, inf_3c90x->IOAddr + regCommandIntStatus_w);
	a3c90x_free_resources(inf_3c90x);
}

static struct net_device_operations a3c90x_operations = {
	.open = a3c90x_open,
	.close = a3c90x_close,
	.poll = a3c90x_poll,
	.transmit = a3c90x_transmit,
	.irq = a3c90x_irq,
};

/**
 * a3c90x_probe: exported routine to probe for the 3c905 card.
 * If this routine is called, the pci functions did find the
 * card.  We read the eeprom here and get the MAC address.
 * Initialization is done in a3c90x_open().
 *
 * @v pci	PCI device info
 * @ pci_id	PCI device IDs
 *
 * @ret rc	Returns 0 on success, negative on failure
 */
static int a3c90x_probe(struct pci_device *pci)
{

	struct net_device *netdev;
	struct INF_3C90X *inf_3c90x;
	unsigned char *HWAddr;
	int rc;

	DBGP("a3c90x_probe\n");

	if (pci->ioaddr == 0)
		return -EINVAL;

	netdev = alloc_etherdev(sizeof(*inf_3c90x));
	if (!netdev)
		return -ENOMEM;

	netdev_init(netdev, &a3c90x_operations);
	pci_set_drvdata(pci, netdev);
	netdev->dev = &pci->dev;

	inf_3c90x = netdev_priv(netdev);
	memset(inf_3c90x, 0, sizeof(*inf_3c90x));

	adjust_pci_device(pci);

	inf_3c90x->is3c556 = (pci->device == 0x6055);
	inf_3c90x->IOAddr = pci->ioaddr;
	inf_3c90x->CurrentWindow = winNone;

	inf_3c90x->isBrev = 1;
	switch (pci->device) {
	case 0x9000:		/* 10 Base TPO             */
	case 0x9001:		/* 10/100 T4               */
	case 0x9050:		/* 10/100 TPO              */
	case 0x9051:		/* 10 Base Combo           */
		inf_3c90x->isBrev = 0;
		break;
	}

	DBG2("[3c90x]: found NIC(0x%04X, 0x%04X), isBrev=%d, is3c556=%d\n",
	    pci->vendor, pci->device, inf_3c90x->isBrev,
	    inf_3c90x->is3c556);

	/* initialize nvs device */
	inf_3c90x->nvs.word_len_log2 = 1;	/* word */
	inf_3c90x->nvs.size = (inf_3c90x->isBrev ? 0x20 : 0x17);
	inf_3c90x->nvs.block_size = 1;
	inf_3c90x->nvs.read = a3c90x_internal_ReadEeprom;
	inf_3c90x->nvs.write = a3c90x_internal_WriteEeprom;

	/* reset NIC before accessing any data from it */
	a3c90x_reset(inf_3c90x);

	/* load eeprom contents to inf_3c90x->eeprom */
	a3c90x_internal_ReadEepromContents(inf_3c90x);

	HWAddr = netdev->hw_addr;

	/* Retrieve the Hardware address */
	HWAddr[0] = inf_3c90x->eeprom[eepromHwAddrOffset + 0] >> 8;
	HWAddr[1] = inf_3c90x->eeprom[eepromHwAddrOffset + 0] & 0xFF;
	HWAddr[2] = inf_3c90x->eeprom[eepromHwAddrOffset + 1] >> 8;
	HWAddr[3] = inf_3c90x->eeprom[eepromHwAddrOffset + 1] & 0xFF;
	HWAddr[4] = inf_3c90x->eeprom[eepromHwAddrOffset + 2] >> 8;
	HWAddr[5] = inf_3c90x->eeprom[eepromHwAddrOffset + 2] & 0xFF;

	if ((rc = register_netdev(netdev)) != 0) {
		DBG("3c90x: register_netdev() failed\n");
		netdev_put(netdev);
		return rc;
	}

	/* we don't handle linkstates yet, so we're always up */
	netdev_link_up(netdev);

	return 0;
}

static struct pci_device_id a3c90x_nics[] = {
/* Original 90x revisions: */
	PCI_ROM(0x10b7, 0x6055, "3c556", "3C556", 0),	/* Huricane */
	PCI_ROM(0x10b7, 0x9000, "3c905-tpo", "3Com900-TPO", 0),	/* 10 Base TPO */
	PCI_ROM(0x10b7, 0x9001, "3c905-t4", "3Com900-Combo", 0),	/* 10/100 T4 */
	PCI_ROM(0x10b7, 0x9050, "3c905-tpo100", "3Com905-TX", 0),	/* 100 Base TX / 10/100 TPO */
	PCI_ROM(0x10b7, 0x9051, "3c905-combo", "3Com905-T4", 0),	/* 100 Base T4 / 10 Base Combo */
/* Newer 90xB revisions: */
	PCI_ROM(0x10b7, 0x9004, "3c905b-tpo", "3Com900B-TPO", 0),	/* 10 Base TPO */
	PCI_ROM(0x10b7, 0x9005, "3c905b-combo", "3Com900B-Combo", 0),	/* 10 Base Combo */
	PCI_ROM(0x10b7, 0x9006, "3c905b-tpb2", "3Com900B-2/T", 0),	/* 10 Base TP and Base2 */
	PCI_ROM(0x10b7, 0x900a, "3c905b-fl", "3Com900B-FL", 0),	/* 10 Base FL */
	PCI_ROM(0x10b7, 0x9055, "3c905b-tpo100", "3Com905B-TX", 0),	/* 10/100 TPO */
	PCI_ROM(0x10b7, 0x9056, "3c905b-t4", "3Com905B-T4", 0),	/* 10/100 T4 */
	PCI_ROM(0x10b7, 0x9058, "3c905b-9058", "3Com905B-9058", 0),	/* Cyclone 10/100/BNC */
	PCI_ROM(0x10b7, 0x905a, "3c905b-fx", "3Com905B-FL", 0),	/* 100 Base FX / 10 Base FX */
/* Newer 90xC revision: */
	PCI_ROM(0x10b7, 0x9200, "3c905c-tpo", "3Com905C-TXM", 0),	/* 10/100 TPO (3C905C-TXM) */
	PCI_ROM(0x10b7, 0x9202, "3c920b-emb-ati", "3c920B-EMB-WNM (ATI Radeon 9100 IGP)", 0),	/* 3c920B-EMB-WNM (ATI Radeon 9100 IGP) */
	PCI_ROM(0x10b7, 0x9210, "3c920b-emb-wnm", "3Com20B-EMB WNM", 0),
	PCI_ROM(0x10b7, 0x9800, "3c980", "3Com980-Cyclone", 0),	/* Cyclone */
	PCI_ROM(0x10b7, 0x9805, "3c9805", "3Com9805", 0),	/* Dual Port Server Cyclone */
	PCI_ROM(0x10b7, 0x7646, "3csoho100-tx", "3CSOHO100-TX", 0),	/* Hurricane */
	PCI_ROM(0x10b7, 0x4500, "3c450", "3Com450 HomePNA Tornado", 0),
	PCI_ROM(0x10b7, 0x1201, "3c982a", "3Com982A", 0),
	PCI_ROM(0x10b7, 0x1202, "3c982b", "3Com982B", 0),
};

struct pci_driver a3c90x_driver __pci_driver = {
	.ids = a3c90x_nics,
	.id_count = (sizeof(a3c90x_nics) / sizeof(a3c90x_nics[0])),
	.probe = a3c90x_probe,
	.remove = a3c90x_remove,
};

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 * End:
 */
