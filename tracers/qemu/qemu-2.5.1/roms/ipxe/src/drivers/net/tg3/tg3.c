
FILE_LICENCE ( GPL2_ONLY );

#include <mii.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <byteswap.h>
#include <ipxe/pci.h>
#include <ipxe/iobuf.h>
#include <ipxe/timer.h>
#include <ipxe/malloc.h>
#include <ipxe/if_ether.h>
#include <ipxe/ethernet.h>
#include <ipxe/netdevice.h>

#include "tg3.h"

#define TG3_DEF_RX_MODE		0
#define TG3_DEF_TX_MODE		0

static void tg3_refill_prod_ring(struct tg3 *tp);

/* Do not place this n-ring entries value into the tp struct itself,
 * we really want to expose these constants to GCC so that modulo et
 * al.  operations are done with shifts and masks instead of with
 * hw multiply/modulo instructions.  Another solution would be to
 * replace things like '% foo' with '& (foo - 1)'.
 */

#define TG3_TX_RING_BYTES	(sizeof(struct tg3_tx_buffer_desc) * \
				 TG3_TX_RING_SIZE)

/* FIXME: does TG3_RX_RET_MAX_SIZE_5705 work for all cards? */
#define TG3_RX_RCB_RING_BYTES(tp) \
	(sizeof(struct tg3_rx_buffer_desc) * (TG3_RX_RET_MAX_SIZE_5705))

#define TG3_RX_STD_RING_BYTES(tp) \
	(sizeof(struct tg3_rx_buffer_desc) * TG3_RX_STD_MAX_SIZE_5700)

void tg3_rx_prodring_fini(struct tg3_rx_prodring_set *tpr)
{	DBGP("%s\n", __func__);

	if (tpr->rx_std) {
		free_dma(tpr->rx_std, TG3_RX_STD_RING_BYTES(tp));
		tpr->rx_std = NULL;
	}
}

/*
 * Must not be invoked with interrupt sources disabled and
 * the hardware shutdown down.
 */
static void tg3_free_consistent(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	if (tp->tx_ring) {
		free_dma(tp->tx_ring, TG3_TX_RING_BYTES);
		tp->tx_ring = NULL;
	}

	free(tp->tx_buffers);
	tp->tx_buffers = NULL;

	if (tp->rx_rcb) {
		free_dma(tp->rx_rcb, TG3_RX_RCB_RING_BYTES(tp));
		tp->rx_rcb_mapping = 0;
		tp->rx_rcb = NULL;
	}

	tg3_rx_prodring_fini(&tp->prodring);

	if (tp->hw_status) {
		free_dma(tp->hw_status, TG3_HW_STATUS_SIZE);
		tp->status_mapping = 0;
		tp->hw_status = NULL;
	}
}

/*
 * Must not be invoked with interrupt sources disabled and
 * the hardware shutdown down.  Can sleep.
 */
int tg3_alloc_consistent(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	struct tg3_hw_status *sblk;
	struct tg3_rx_prodring_set *tpr = &tp->prodring;

	tp->hw_status = malloc_dma(TG3_HW_STATUS_SIZE, TG3_DMA_ALIGNMENT);
	if (!tp->hw_status) {
		DBGC(tp->dev, "hw_status alloc failed\n");
		goto err_out;
	}
	tp->status_mapping = virt_to_bus(tp->hw_status);

	memset(tp->hw_status, 0, TG3_HW_STATUS_SIZE);
	sblk = tp->hw_status;

	tpr->rx_std = malloc_dma(TG3_RX_STD_RING_BYTES(tp), TG3_DMA_ALIGNMENT);
	if (!tpr->rx_std) {
		DBGC(tp->dev, "rx prodring alloc failed\n");
		goto err_out;
	}
	tpr->rx_std_mapping = virt_to_bus(tpr->rx_std);
	memset(tpr->rx_std, 0, TG3_RX_STD_RING_BYTES(tp));

	tp->tx_buffers = zalloc(sizeof(struct ring_info) * TG3_TX_RING_SIZE);
	if (!tp->tx_buffers)
		goto err_out;

	tp->tx_ring = malloc_dma(TG3_TX_RING_BYTES, TG3_DMA_ALIGNMENT);
	if (!tp->tx_ring)
		goto err_out;
	tp->tx_desc_mapping = virt_to_bus(tp->tx_ring);

	/*
	 * When RSS is enabled, the status block format changes
	 * slightly.  The "rx_jumbo_consumer", "reserved",
	 * and "rx_mini_consumer" members get mapped to the
	 * other three rx return ring producer indexes.
	 */

	tp->rx_rcb_prod_idx = &sblk->idx[0].rx_producer;

	tp->rx_rcb = malloc_dma(TG3_RX_RCB_RING_BYTES(tp), TG3_DMA_ALIGNMENT);
	if (!tp->rx_rcb)
		goto err_out;
	tp->rx_rcb_mapping = virt_to_bus(tp->rx_rcb);

	memset(tp->rx_rcb, 0, TG3_RX_RCB_RING_BYTES(tp));

	return 0;

err_out:
	tg3_free_consistent(tp);
	return -ENOMEM;
}

#define TG3_RX_STD_BUFF_RING_BYTES(tp) \
	(sizeof(struct ring_info) * TG3_RX_STD_MAX_SIZE_5700)
#define TG3_RX_STD_RING_BYTES(tp) \
	(sizeof(struct tg3_rx_buffer_desc) * TG3_RX_STD_MAX_SIZE_5700)

/* Initialize rx rings for packet processing.
 *
 * The chip has been shut down and the driver detached from
 * the networking, so no interrupts or new tx packets will
 * end up in the driver.
 */
static int tg3_rx_prodring_alloc(struct tg3 __unused *tp,
				 struct tg3_rx_prodring_set *tpr)
{	DBGP("%s\n", __func__);

	u32 i;

	tpr->rx_std_cons_idx = 0;
	tpr->rx_std_prod_idx = 0;

	/* Initialize invariants of the rings, we only set this
	 * stuff once.  This works because the card does not
	 * write into the rx buffer posting rings.
	 */
	/* FIXME: does TG3_RX_STD_MAX_SIZE_5700 work on all cards? */
	for (i = 0; i < TG3_RX_STD_MAX_SIZE_5700; i++) {
		struct tg3_rx_buffer_desc *rxd;

		rxd = &tpr->rx_std[i];
		rxd->idx_len = (TG3_RX_STD_DMA_SZ - 64 - 2) << RXD_LEN_SHIFT;
		rxd->type_flags = (RXD_FLAG_END << RXD_FLAGS_SHIFT);
		rxd->opaque = (RXD_OPAQUE_RING_STD |
			       (i << RXD_OPAQUE_INDEX_SHIFT));
	}

	return 0;
}

static void tg3_rx_iob_free(struct io_buffer *iobs[], int i)
{	DBGP("%s\n", __func__);

	if (iobs[i] == NULL)
		return;

	free_iob(iobs[i]);
	iobs[i] = NULL;
}

static void tg3_rx_prodring_free(struct tg3_rx_prodring_set *tpr)
{	DBGP("%s\n", __func__);

	unsigned int i;

	for (i = 0; i < TG3_DEF_RX_RING_PENDING; i++)
		tg3_rx_iob_free(tpr->rx_iobufs, i);
}

/* Initialize tx/rx rings for packet processing.
 *
 * The chip has been shut down and the driver detached from
 * the networking, so no interrupts or new tx packets will
 * end up in the driver.
 */
int tg3_init_rings(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	/* Free up all the SKBs. */
///	tg3_free_rings(tp);

	tp->last_tag = 0;
	tp->last_irq_tag = 0;
	tp->hw_status->status = 0;
	tp->hw_status->status_tag = 0;
	memset(tp->hw_status, 0, TG3_HW_STATUS_SIZE);

	tp->tx_prod = 0;
	tp->tx_cons = 0;
	if (tp->tx_ring)
		memset(tp->tx_ring, 0, TG3_TX_RING_BYTES);

	tp->rx_rcb_ptr = 0;
	if (tp->rx_rcb)
		memset(tp->rx_rcb, 0, TG3_RX_RCB_RING_BYTES(tp));

	if (tg3_rx_prodring_alloc(tp, &tp->prodring)) {
		DBGC(tp->dev, "tg3_rx_prodring_alloc() failed\n");
		tg3_rx_prodring_free(&tp->prodring);
		return -ENOMEM;
	}

	return 0;
}

static int tg3_open(struct net_device *dev)
{	DBGP("%s\n", __func__);

	struct tg3 *tp = netdev_priv(dev);
	struct tg3_rx_prodring_set *tpr = &tp->prodring;
	int err = 0;

	tg3_set_power_state_0(tp);

	/* Initialize MAC address and backoff seed. */
	__tg3_set_mac_addr(tp, 0);

	err = tg3_alloc_consistent(tp);
	if (err)
		return err;

	tpr->rx_std_iob_cnt = 0;

	err = tg3_init_hw(tp, 1);
	if (err != 0)
		DBGC(tp->dev, "tg3_init_hw failed: %s\n", strerror(err));
	else
		tg3_refill_prod_ring(tp);

	return err;
}

static inline u32 tg3_tx_avail(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	/* Tell compiler to fetch tx indices from memory. */
	barrier();
	return TG3_DEF_TX_RING_PENDING -
	       ((tp->tx_prod - tp->tx_cons) & (TG3_TX_RING_SIZE - 1));
}

#if 0
/**
 *
 * Prints all registers that could cause a set ERR bit in hw_status->status
 */
static void tg3_dump_err_reg(struct tg3 *tp)
{	DBGP("%s\n", __func__);

		printf("FLOW_ATTN: %#08x\n", tr32(HOSTCC_FLOW_ATTN));
		printf("MAC ATTN: %#08x\n", tr32(MAC_STATUS));
		printf("MSI STATUS: %#08x\n", tr32(MSGINT_STATUS));
		printf("DMA RD: %#08x\n", tr32(RDMAC_STATUS));
		printf("DMA WR: %#08x\n", tr32(WDMAC_STATUS));
		printf("TX CPU STATE: %#08x\n", tr32(TX_CPU_STATE));
		printf("RX CPU STATE: %#08x\n", tr32(RX_CPU_STATE));
}

static void __unused tw32_mailbox2(struct tg3 *tp, uint32_t reg, uint32_t val)
{	DBGP("%s\n", __func__);

	tw32_mailbox(reg, val);
	tr32(reg);
}
#endif

#define NEXT_TX(N)		(((N) + 1) & (TG3_TX_RING_SIZE - 1))

/* hard_start_xmit for devices that have the 4G bug and/or 40-bit bug and
 * support TG3_FLAG_HW_TSO_1 or firmware TSO only.
 */
static int tg3_transmit(struct net_device *dev, struct io_buffer *iob)
{	DBGP("%s\n", __func__);

	struct tg3 *tp = netdev_priv(dev);
	u32 len, entry;
	dma_addr_t mapping;

	if (tg3_tx_avail(tp) < 1) {
		DBGC(dev, "Transmit ring full\n");
		return -ENOBUFS;
	}

	entry = tp->tx_prod;

	iob_pad(iob, ETH_ZLEN);
	mapping = virt_to_bus(iob->data);
	len = iob_len(iob);

	tp->tx_buffers[entry].iob = iob;

	tg3_set_txd(tp, entry, mapping, len, TXD_FLAG_END);

	entry = NEXT_TX(entry);

	/* Packets are ready, update Tx producer idx local and on card. */
	tw32_tx_mbox(tp->prodmbox, entry);

	tp->tx_prod = entry;

	mb();

	return 0;
}

static void tg3_tx_complete(struct net_device *dev)
{	DBGP("%s\n", __func__);

	struct tg3 *tp = netdev_priv(dev);
	u32 hw_idx = tp->hw_status->idx[0].tx_consumer;
	u32 sw_idx = tp->tx_cons;

	while (sw_idx != hw_idx) {
		struct io_buffer *iob = tp->tx_buffers[sw_idx].iob;

		DBGC2(dev, "Transmitted packet: %zd bytes\n", iob_len(iob));

		netdev_tx_complete(dev, iob);
		sw_idx = NEXT_TX(sw_idx);
	}

	tp->tx_cons = sw_idx;
}

#define TG3_RX_STD_BUFF_RING_BYTES(tp) \
	(sizeof(struct ring_info) * TG3_RX_STD_MAX_SIZE_5700)
#define TG3_RX_STD_RING_BYTES(tp) \
	(sizeof(struct tg3_rx_buffer_desc) * TG3_RX_STD_MAX_SIZE_5700)

/* Returns 0 or < 0 on error.
 *
 * We only need to fill in the address because the other members
 * of the RX descriptor are invariant, see tg3_init_rings.
 *
 * Note the purposeful assymetry of cpu vs. chip accesses.  For
 * posting buffers we only dirty the first cache line of the RX
 * descriptor (containing the address).  Whereas for the RX status
 * buffers the cpu only reads the last cacheline of the RX descriptor
 * (to fetch the error flags, vlan tag, checksum, and opaque cookie).
 */
static int tg3_alloc_rx_iob(struct tg3_rx_prodring_set *tpr, u32 dest_idx_unmasked)
{	DBGP("%s\n", __func__);

	struct tg3_rx_buffer_desc *desc;
	struct io_buffer *iob;
	dma_addr_t mapping;
	int dest_idx, iob_idx;

	dest_idx = dest_idx_unmasked & (TG3_RX_STD_MAX_SIZE_5700 - 1);
	desc = &tpr->rx_std[dest_idx];

	/* Do not overwrite any of the map or rp information
	 * until we are sure we can commit to a new buffer.
	 *
	 * Callers depend upon this behavior and assume that
	 * we leave everything unchanged if we fail.
	 */
	iob = alloc_iob(TG3_RX_STD_DMA_SZ);
	if (iob == NULL)
		return -ENOMEM;

	iob_idx = dest_idx % TG3_DEF_RX_RING_PENDING;
	tpr->rx_iobufs[iob_idx] = iob;

	mapping = virt_to_bus(iob->data);

	desc->addr_hi = ((u64)mapping >> 32);
	desc->addr_lo = ((u64)mapping & 0xffffffff);

	return 0;
}

static void tg3_refill_prod_ring(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	struct tg3_rx_prodring_set *tpr = &tp->prodring;
	int idx = tpr->rx_std_prod_idx;

	DBGCP(tp->dev, "%s\n", __func__);

	while (tpr->rx_std_iob_cnt < TG3_DEF_RX_RING_PENDING) {
		if (tpr->rx_iobufs[idx % TG3_DEF_RX_RING_PENDING] == NULL) {
			if (tg3_alloc_rx_iob(tpr, idx) < 0) {
				DBGC(tp->dev, "alloc_iob() failed for descriptor %d\n", idx);
				break;
			}
			DBGC2(tp->dev, "allocated iob_buffer for descriptor %d\n", idx);
		}

		idx = (idx + 1) % TG3_RX_STD_MAX_SIZE_5700;
		tpr->rx_std_iob_cnt++;
	}

	if ((u32)idx != tpr->rx_std_prod_idx) {
		tpr->rx_std_prod_idx = idx;
		tw32_rx_mbox(TG3_RX_STD_PROD_IDX_REG, idx);
	}
}

static void tg3_rx_complete(struct net_device *dev)
{	DBGP("%s\n", __func__);

	struct tg3 *tp = netdev_priv(dev);

	u32 sw_idx = tp->rx_rcb_ptr;
	u16 hw_idx;
	struct tg3_rx_prodring_set *tpr = &tp->prodring;

	hw_idx = *(tp->rx_rcb_prod_idx);

	while (sw_idx != hw_idx) {
		struct tg3_rx_buffer_desc *desc = &tp->rx_rcb[sw_idx];
		u32 desc_idx = desc->opaque & RXD_OPAQUE_INDEX_MASK;
		int iob_idx = desc_idx % TG3_DEF_RX_RING_PENDING;
		struct io_buffer *iob = tpr->rx_iobufs[iob_idx];
		unsigned int len;

		DBGC2(dev, "RX - desc_idx: %d sw_idx: %d hw_idx: %d\n", desc_idx, sw_idx, hw_idx);

		assert(iob != NULL);

		if ((desc->err_vlan & RXD_ERR_MASK) != 0 &&
		    (desc->err_vlan != RXD_ERR_ODD_NIBBLE_RCVD_MII)) {
			/* drop packet */
			DBGC(dev, "Corrupted packet received\n");
			netdev_rx_err(dev, iob, -EINVAL);
		} else {
			len = ((desc->idx_len & RXD_LEN_MASK) >> RXD_LEN_SHIFT) -
			        ETH_FCS_LEN;
			iob_put(iob, len);
			netdev_rx(dev, iob);

			DBGC2(dev, "Received packet: %d bytes %d %d\n", len, sw_idx, hw_idx);
		}

		sw_idx++;
		sw_idx &= TG3_RX_RET_MAX_SIZE_5705 - 1;

		tpr->rx_iobufs[iob_idx] = NULL;
		tpr->rx_std_iob_cnt--;
	}

	if (tp->rx_rcb_ptr != sw_idx) {
		tw32_rx_mbox(tp->consmbox, sw_idx);
		tp->rx_rcb_ptr = sw_idx;
	}

	tg3_refill_prod_ring(tp);
}

static void tg3_poll(struct net_device *dev)
{	DBGP("%s\n", __func__);

	struct tg3 *tp = netdev_priv(dev);

	/* ACK interrupts */
	/*
	 *tw32_mailbox_f(MAILBOX_INTERRUPT_0 + TG3_64BIT_REG_LOW, 0x00);
	 */
	tp->hw_status->status &= ~SD_STATUS_UPDATED;

	tg3_poll_link(tp);
	tg3_tx_complete(dev);
	tg3_rx_complete(dev);
}

static void tg3_close(struct net_device *dev)
{	DBGP("%s\n", __func__);

	struct tg3 *tp = netdev_priv(dev);

	DBGP("%s\n", __func__);

	tg3_halt(tp);
	tg3_rx_prodring_free(&tp->prodring);
	tg3_flag_clear(tp, INIT_COMPLETE);

	tg3_free_consistent(tp);

}

static void tg3_irq(struct net_device *dev, int enable)
{	DBGP("%s\n", __func__);

	struct tg3 *tp = netdev_priv(dev);

	DBGP("%s: %d\n", __func__, enable);

	if (enable)
		tg3_enable_ints(tp);
	else
		tg3_disable_ints(tp);
}

static struct net_device_operations tg3_netdev_ops = {
	.open = tg3_open,
	.close = tg3_close,
	.poll = tg3_poll,
	.transmit = tg3_transmit,
	.irq = tg3_irq,
};

#define TEST_BUFFER_SIZE	0x2000

int tg3_do_test_dma(struct tg3 *tp, u32 __unused *buf, dma_addr_t buf_dma, int size, int to_device);
void tg3_read_mem(struct tg3 *tp, u32 off, u32 *val);

static int tg3_test_dma(struct tg3 *tp)
{	DBGP("%s\n", __func__);

	dma_addr_t buf_dma;
	u32 *buf;
	int ret = 0;

	buf = malloc_dma(TEST_BUFFER_SIZE, TG3_DMA_ALIGNMENT);
	if (!buf) {
		ret = -ENOMEM;
		goto out_nofree;
	}
	buf_dma = virt_to_bus(buf);
	DBGC2(tp->dev, "dma test buffer, virt: %p phys: %#08x\n", buf, buf_dma);

	if (tg3_flag(tp, 57765_PLUS)) {
		tp->dma_rwctrl = DMA_RWCTRL_DIS_CACHE_ALIGNMENT;
		goto out;
	}

	tp->dma_rwctrl = ((0x7 << DMA_RWCTRL_PCI_WRITE_CMD_SHIFT) |
	                 (0x6 << DMA_RWCTRL_PCI_READ_CMD_SHIFT));

	if (tg3_flag(tp, PCI_EXPRESS)) {
		/* DMA read watermark not used on PCIE */
		tp->dma_rwctrl |= 0x00180000;
	} else if (!tg3_flag(tp, PCIX_MODE)) {
		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5705 ||
		    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5750)
			tp->dma_rwctrl |= 0x003f0000;
		else
			tp->dma_rwctrl |= 0x003f000f;
	} else {
		if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703 ||
		    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704) {
			u32 ccval = (tr32(TG3PCI_CLOCK_CTRL) & 0x1f);
			u32 read_water = 0x7;

			if (ccval == 0x6 || ccval == 0x7)
				tp->dma_rwctrl |= DMA_RWCTRL_ONE_DMA;

			if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703)
				read_water = 4;
			/* Set bit 23 to enable PCIX hw bug fix */
			tp->dma_rwctrl |=
				(read_water << DMA_RWCTRL_READ_WATER_SHIFT) |
				(0x3 << DMA_RWCTRL_WRITE_WATER_SHIFT) |
				(1 << 23);
		} else if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5780) {
			/* 5780 always in PCIX mode */
			tp->dma_rwctrl |= 0x00144000;
		} else if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5714) {
			/* 5714 always in PCIX mode */
			tp->dma_rwctrl |= 0x00148000;
		} else {
			tp->dma_rwctrl |= 0x001b000f;
		}
	}

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5703 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5704)
		tp->dma_rwctrl &= 0xfffffff0;

	if (GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5700 ||
	    GET_ASIC_REV(tp->pci_chip_rev_id) == ASIC_REV_5701) {
		/* Remove this if it causes problems for some boards. */
		tp->dma_rwctrl |= DMA_RWCTRL_USE_MEM_READ_MULT;

		/* On 5700/5701 chips, we need to set this bit.
		 * Otherwise the chip will issue cacheline transactions
		 * to streamable DMA memory with not all the byte
		 * enables turned on.  This is an error on several
		 * RISC PCI controllers, in particular sparc64.
		 *
		 * On 5703/5704 chips, this bit has been reassigned
		 * a different meaning.  In particular, it is used
		 * on those chips to enable a PCI-X workaround.
		 */
		tp->dma_rwctrl |= DMA_RWCTRL_ASSERT_ALL_BE;
	}

	tw32(TG3PCI_DMA_RW_CTRL, tp->dma_rwctrl);

#if 0
	/* Unneeded, already done by tg3_get_invariants.  */
	tg3_switch_clocks(tp);
#endif

	if (GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5700 &&
	    GET_ASIC_REV(tp->pci_chip_rev_id) != ASIC_REV_5701)
		goto out;

	/* It is best to perform DMA test with maximum write burst size
	 * to expose the 5700/5701 write DMA bug.
	 */
	tp->dma_rwctrl &= ~DMA_RWCTRL_WRITE_BNDRY_MASK;
	tw32(TG3PCI_DMA_RW_CTRL, tp->dma_rwctrl);

	while (1) {
		u32 *p = buf, i;

		for (i = 0; i < TEST_BUFFER_SIZE / sizeof(u32); i++)
			p[i] = i;

		/* Send the buffer to the chip. */
		ret = tg3_do_test_dma(tp, buf, buf_dma, TEST_BUFFER_SIZE, 1);
		if (ret) {
			DBGC(&tp->pdev->dev,
				"%s: Buffer write failed. err = %d\n",
				__func__, ret);
			break;
		}

		/* validate data reached card RAM correctly. */
		for (i = 0; i < TEST_BUFFER_SIZE / sizeof(u32); i++) {
			u32 val;
			tg3_read_mem(tp, 0x2100 + (i*4), &val);
			if (le32_to_cpu(val) != p[i]) {
				DBGC(&tp->pdev->dev,
					"%s: Buffer corrupted on device! "
					"(%d != %d)\n", __func__, val, i);
				/* ret = -ENODEV here? */
			}
			p[i] = 0;
		}

		/* Now read it back. */
		ret = tg3_do_test_dma(tp, buf, buf_dma, TEST_BUFFER_SIZE, 0);
		if (ret) {
			DBGC(&tp->pdev->dev, "%s: Buffer read failed. "
				"err = %d\n", __func__, ret);
			break;
		}

		/* Verify it. */
		for (i = 0; i < TEST_BUFFER_SIZE / sizeof(u32); i++) {
			if (p[i] == i)
				continue;

			if ((tp->dma_rwctrl & DMA_RWCTRL_WRITE_BNDRY_MASK) !=
			    DMA_RWCTRL_WRITE_BNDRY_16) {
				tp->dma_rwctrl &= ~DMA_RWCTRL_WRITE_BNDRY_MASK;
				tp->dma_rwctrl |= DMA_RWCTRL_WRITE_BNDRY_16;
				tw32(TG3PCI_DMA_RW_CTRL, tp->dma_rwctrl);
				break;
			} else {
				DBGC(&tp->pdev->dev,
					"%s: Buffer corrupted on read back! "
					"(%d != %d)\n", __func__, p[i], i);
				ret = -ENODEV;
				goto out;
			}
		}

		if (i == (TEST_BUFFER_SIZE / sizeof(u32))) {
			/* Success. */
			ret = 0;
			break;
		}
	}

	if ((tp->dma_rwctrl & DMA_RWCTRL_WRITE_BNDRY_MASK) !=
	    DMA_RWCTRL_WRITE_BNDRY_16) {
		/* DMA test passed without adjusting DMA boundary,
		 * now look for chipsets that are known to expose the
		 * DMA bug without failing the test.
		 */
		tp->dma_rwctrl &= ~DMA_RWCTRL_WRITE_BNDRY_MASK;
		tp->dma_rwctrl |= DMA_RWCTRL_WRITE_BNDRY_16;

		tw32(TG3PCI_DMA_RW_CTRL, tp->dma_rwctrl);
	}

out:
	free_dma(buf, TEST_BUFFER_SIZE);
out_nofree:
	return ret;
}

static int tg3_init_one(struct pci_device *pdev)
{	DBGP("%s\n", __func__);

	struct net_device *dev;
	struct tg3 *tp;
	int err = 0;
	unsigned long reg_base, reg_size;

	adjust_pci_device(pdev);

	dev = alloc_etherdev(sizeof(*tp));
	if (!dev) {
		DBGC(&pdev->dev, "Failed to allocate etherdev\n");
		err = -ENOMEM;
		goto err_out_disable_pdev;
	}

	netdev_init(dev, &tg3_netdev_ops);
	pci_set_drvdata(pdev, dev);

	dev->dev = &pdev->dev;

	tp = netdev_priv(dev);
	tp->pdev = pdev;
	tp->dev = dev;
	tp->rx_mode = TG3_DEF_RX_MODE;
	tp->tx_mode = TG3_DEF_TX_MODE;

	/* Subsystem IDs are required later */
	pci_read_config_word(tp->pdev, PCI_SUBSYSTEM_VENDOR_ID, &tp->subsystem_vendor);
	pci_read_config_word(tp->pdev, PCI_SUBSYSTEM_ID, &tp->subsystem_device);

	/* The word/byte swap controls here control register access byte
	 * swapping.  DMA data byte swapping is controlled in the GRC_MODE
	 * setting below.
	 */
	tp->misc_host_ctrl =
		MISC_HOST_CTRL_MASK_PCI_INT |
		MISC_HOST_CTRL_WORD_SWAP |
		MISC_HOST_CTRL_INDIR_ACCESS |
		MISC_HOST_CTRL_PCISTATE_RW;

	/* The NONFRM (non-frame) byte/word swap controls take effect
	 * on descriptor entries, anything which isn't packet data.
	 *
	 * The StrongARM chips on the board (one for tx, one for rx)
	 * are running in big-endian mode.
	 */
	tp->grc_mode = (GRC_MODE_WSWAP_DATA | GRC_MODE_BSWAP_DATA |
			GRC_MODE_WSWAP_NONFRM_DATA);
#if __BYTE_ORDER == __BIG_ENDIAN
	tp->grc_mode |= GRC_MODE_BSWAP_NONFRM_DATA;
#endif

	/* FIXME: how can we detect errors here? */
	reg_base = pci_bar_start(pdev, PCI_BASE_ADDRESS_0);
	reg_size = pci_bar_size(pdev, PCI_BASE_ADDRESS_0);

	tp->regs = ioremap(reg_base, reg_size);
	if (!tp->regs) {
		DBGC(&pdev->dev, "Failed to remap device registers\n");
		errno = -ENOENT;
		goto err_out_disable_pdev;
	}

	err = tg3_get_invariants(tp);
	if (err) {
		DBGC(&pdev->dev, "Problem fetching invariants of chip, aborting\n");
		goto err_out_iounmap;
	}

	tg3_init_bufmgr_config(tp);

	err = tg3_get_device_address(tp);
	if (err) {
		DBGC(&pdev->dev, "Could not obtain valid ethernet address, aborting\n");
		goto err_out_iounmap;
	}

	/*
	 * Reset chip in case UNDI or EFI driver did not shutdown
	 * DMA self test will enable WDMAC and we'll see (spurious)
	 * pending DMA on the PCI bus at that point.
	 */
	if ((tr32(HOSTCC_MODE) & HOSTCC_MODE_ENABLE) ||
	    (tr32(WDMAC_MODE) & WDMAC_MODE_ENABLE)) {
		tw32(MEMARB_MODE, MEMARB_MODE_ENABLE);
		tg3_halt(tp);
	}

	err = tg3_test_dma(tp);
	if (err) {
		DBGC(&pdev->dev, "DMA engine test failed, aborting\n");
		goto err_out_iounmap;
	}

	tp->int_mbox = MAILBOX_INTERRUPT_0 + TG3_64BIT_REG_LOW;
	tp->consmbox = MAILBOX_RCVRET_CON_IDX_0 + TG3_64BIT_REG_LOW;
	tp->prodmbox = MAILBOX_SNDHOST_PROD_IDX_0 + TG3_64BIT_REG_LOW;

	tp->coal_now = HOSTCC_MODE_NOW;

	err = register_netdev(dev);
	if (err) {
		DBGC(&pdev->dev, "Cannot register net device, aborting\n");
		goto err_out_iounmap;
	}

	/* Call tg3_setup_phy() to start autoneg process, which saves time
	 * over starting autoneg in tg3_open();
	 */
	err = tg3_setup_phy(tp, 0);
	if (err) {
		DBGC(tp->dev, "tg3_setup_phy() call failed in %s\n", __func__);
		goto err_out_iounmap;
	}

	return 0;

err_out_iounmap:
	if (tp->regs) {
		iounmap(tp->regs);
		tp->regs = NULL;
	}

	netdev_put(dev);

err_out_disable_pdev:
	pci_set_drvdata(pdev, NULL);
	return err;
}

static void tg3_remove_one(struct pci_device *pci)
{	DBGP("%s\n", __func__);

	struct net_device *netdev = pci_get_drvdata(pci);

	unregister_netdev(netdev);
	netdev_nullify(netdev);
	netdev_put(netdev);
}

static struct pci_device_id tg3_nics[] = {
	PCI_ROM(0x14e4, 0x1644, "14e4-1644", "14e4-1644", 0),
	PCI_ROM(0x14e4, 0x1645, "14e4-1645", "14e4-1645", 0),
	PCI_ROM(0x14e4, 0x1646, "14e4-1646", "14e4-1646", 0),
	PCI_ROM(0x14e4, 0x1647, "14e4-1647", "14e4-1647", 0),
	PCI_ROM(0x14e4, 0x1648, "14e4-1648", "14e4-1648", 0),
	PCI_ROM(0x14e4, 0x164d, "14e4-164d", "14e4-164d", 0),
	PCI_ROM(0x14e4, 0x1653, "14e4-1653", "14e4-1653", 0),
	PCI_ROM(0x14e4, 0x1654, "14e4-1654", "14e4-1654", 0),
	PCI_ROM(0x14e4, 0x165d, "14e4-165d", "14e4-165d", 0),
	PCI_ROM(0x14e4, 0x165e, "14e4-165e", "14e4-165e", 0),
	PCI_ROM(0x14e4, 0x16a6, "14e4-16a6", "14e4-16a6", 0),
	PCI_ROM(0x14e4, 0x16a7, "14e4-16a7", "14e4-16a7", 0),
	PCI_ROM(0x14e4, 0x16a8, "14e4-16a8", "14e4-16a8", 0),
	PCI_ROM(0x14e4, 0x16c6, "14e4-16c6", "14e4-16c6", 0),
	PCI_ROM(0x14e4, 0x16c7, "14e4-16c7", "14e4-16c7", 0),
	PCI_ROM(0x14e4, 0x1696, "14e4-1696", "14e4-1696", 0),
	PCI_ROM(0x14e4, 0x169c, "14e4-169c", "14e4-169c", 0),
	PCI_ROM(0x14e4, 0x169d, "14e4-169d", "14e4-169d", 0),
	PCI_ROM(0x14e4, 0x170d, "14e4-170d", "14e4-170d", 0),
	PCI_ROM(0x14e4, 0x170e, "14e4-170e", "14e4-170e", 0),
	PCI_ROM(0x14e4, 0x1649, "14e4-1649", "14e4-1649", 0),
	PCI_ROM(0x14e4, 0x166e, "14e4-166e", "14e4-166e", 0),
	PCI_ROM(0x14e4, 0x1659, "14e4-1659", "14e4-1659", 0),
	PCI_ROM(0x14e4, 0x165a, "14e4-165a", "14e4-165a", 0),
	PCI_ROM(0x14e4, 0x1677, "14e4-1677", "14e4-1677", 0),
	PCI_ROM(0x14e4, 0x167d, "14e4-167d", "14e4-167d", 0),
	PCI_ROM(0x14e4, 0x167e, "14e4-167e", "14e4-167e", 0),
	PCI_ROM(0x14e4, 0x1600, "14e4-1600", "14e4-1600", 0),
	PCI_ROM(0x14e4, 0x1601, "14e4-1601", "14e4-1601", 0),
	PCI_ROM(0x14e4, 0x16f7, "14e4-16f7", "14e4-16f7", 0),
	PCI_ROM(0x14e4, 0x16fd, "14e4-16fd", "14e4-16fd", 0),
	PCI_ROM(0x14e4, 0x16fe, "14e4-16fe", "14e4-16fe", 0),
	PCI_ROM(0x14e4, 0x167a, "14e4-167a", "14e4-167a", 0),
	PCI_ROM(0x14e4, 0x1672, "14e4-1672", "14e4-1672", 0),
	PCI_ROM(0x14e4, 0x167b, "14e4-167b", "14e4-167b", 0),
	PCI_ROM(0x14e4, 0x1673, "14e4-1673", "14e4-1673", 0),
	PCI_ROM(0x14e4, 0x1674, "14e4-1674", "14e4-1674", 0),
	PCI_ROM(0x14e4, 0x169a, "14e4-169a", "14e4-169a", 0),
	PCI_ROM(0x14e4, 0x169b, "14e4-169b", "14e4-169b", 0),
	PCI_ROM(0x14e4, 0x1693, "14e4-1693", "14e4-1693", 0),
	PCI_ROM(0x14e4, 0x167f, "14e4-167f", "14e4-167f", 0),
	PCI_ROM(0x14e4, 0x1668, "14e4-1668", "14e4-1668", 0),
	PCI_ROM(0x14e4, 0x1669, "14e4-1669", "14e4-1669", 0),
	PCI_ROM(0x14e4, 0x1678, "14e4-1678", "14e4-1678", 0),
	PCI_ROM(0x14e4, 0x1679, "14e4-1679", "14e4-1679", 0),
	PCI_ROM(0x14e4, 0x166a, "14e4-166a", "14e4-166a", 0),
	PCI_ROM(0x14e4, 0x166b, "14e4-166b", "14e4-166b", 0),
	PCI_ROM(0x14e4, 0x16dd, "14e4-16dd", "14e4-16dd", 0),
	PCI_ROM(0x14e4, 0x1712, "14e4-1712", "14e4-1712", 0),
	PCI_ROM(0x14e4, 0x1713, "14e4-1713", "14e4-1713", 0),
	PCI_ROM(0x14e4, 0x1698, "14e4-1698", "14e4-1698", 0),
	PCI_ROM(0x14e4, 0x1684, "14e4-1684", "14e4-1684", 0),
	PCI_ROM(0x14e4, 0x165b, "14e4-165b", "14e4-165b", 0),
	PCI_ROM(0x14e4, 0x1681, "14e4-1681", "14e4-1681", 0),
	PCI_ROM(0x14e4, 0x1682, "14e4-1682", "14e4-1682", 0),
	PCI_ROM(0x14e4, 0x1680, "14e4-1680", "14e4-1680", 0),
	PCI_ROM(0x14e4, 0x1688, "14e4-1688", "14e4-1688", 0),
	PCI_ROM(0x14e4, 0x1689, "14e4-1689", "14e4-1689", 0),
	PCI_ROM(0x14e4, 0x1699, "14e4-1699", "14e4-1699", 0),
	PCI_ROM(0x14e4, 0x16a0, "14e4-16a0", "14e4-16a0", 0),
	PCI_ROM(0x14e4, 0x1692, "14e4-1692", "14e4-1692", 0),
	PCI_ROM(0x14e4, 0x1690, "14e4-1690", "14e4-1690", 0),
	PCI_ROM(0x14e4, 0x1694, "14e4-1694", "14e4-1694", 0),
	PCI_ROM(0x14e4, 0x1691, "14e4-1691", "14e4-1691", 0),
	PCI_ROM(0x14e4, 0x1655, "14e4-1655", "14e4-1655", 0),
	PCI_ROM(0x14e4, 0x1656, "14e4-1656", "14e4-1656", 0),
	PCI_ROM(0x14e4, 0x16b1, "14e4-16b1", "14e4-16b1", 0),
	PCI_ROM(0x14e4, 0x16b5, "14e4-16b5", "14e4-16b5", 0),
	PCI_ROM(0x14e4, 0x16b0, "14e4-16b0", "14e4-16b0", 0),
	PCI_ROM(0x14e4, 0x16b4, "14e4-16b4", "14e4-16b4", 0),
	PCI_ROM(0x14e4, 0x16b2, "14e4-16b2", "14e4-16b2", 0),
	PCI_ROM(0x14e4, 0x16b6, "14e4-16b6", "14e4-16b6", 0),
	PCI_ROM(0x14e4, 0x1657, "14e4-1657", "14e4-1657", 0),
	PCI_ROM(0x14e4, 0x165f, "14e4-165f", "14e4-165f", 0),
	PCI_ROM(0x14e4, 0x1686, "14e4-1686", "14e4-1686", 0),
	PCI_ROM(0x1148, 0x4400, "1148-4400", "1148-4400", 0),
	PCI_ROM(0x1148, 0x4500, "1148-4500", "1148-4500", 0),
	PCI_ROM(0x173b, 0x03e8, "173b-03e8", "173b-03e8", 0),
	PCI_ROM(0x173b, 0x03e9, "173b-03e9", "173b-03e9", 0),
	PCI_ROM(0x173b, 0x03eb, "173b-03eb", "173b-03eb", 0),
	PCI_ROM(0x173b, 0x03ea, "173b-03ea", "173b-03ea", 0),
	PCI_ROM(0x106b, 0x1645, "106b-1645", "106b-1645", 0),
};

struct pci_driver tg3_pci_driver __pci_driver = {
	.ids = tg3_nics,
	.id_count = ARRAY_SIZE(tg3_nics),
	.probe = tg3_init_one,
	.remove = tg3_remove_one,
};
