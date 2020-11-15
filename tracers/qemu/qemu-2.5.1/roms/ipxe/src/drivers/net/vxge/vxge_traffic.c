/*
 * vxge-traffic.c: iPXE driver for Neterion Inc's X3100 Series 10GbE
 *              PCIe I/O Virtualized Server Adapter.
 *
 * Copyright(c) 2002-2010 Neterion Inc.
 *
 * This software may be used and distributed according to the terms of
 * the GNU General Public License (GPL), incorporated herein by
 * reference.  Drivers based on or derived from this code fall under
 * the GPL and must retain the authorship, copyright and license
 * notice.
 *
 */

FILE_LICENCE(GPL2_ONLY);

#include <ipxe/netdevice.h>
#include <errno.h>

#include "vxge_traffic.h"
#include "vxge_config.h"
#include "vxge_main.h"

/*
 * vxge_hw_vpath_intr_enable - Enable vpath interrupts.
 * @vpath: Virtual Path handle.
 *
 * Enable vpath interrupts. The function is to be executed the last in
 * vpath initialization sequence.
 *
 * See also: vxge_hw_vpath_intr_disable()
 */
enum vxge_hw_status
vxge_hw_vpath_intr_enable(struct __vxge_hw_virtualpath *vpath)
{
	struct vxge_hw_vpath_reg *vp_reg;
	enum vxge_hw_status status = VXGE_HW_OK;

	if (vpath->vp_open == VXGE_HW_VP_NOT_OPEN) {
		status = VXGE_HW_ERR_VPATH_NOT_OPEN;
	goto exit;
	}

	vp_reg = vpath->vp_reg;

	writeq(VXGE_HW_INTR_MASK_ALL, &vp_reg->kdfcctl_errors_reg);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
				&vp_reg->general_errors_reg);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
				&vp_reg->pci_config_errors_reg);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
				&vp_reg->mrpcim_to_vpath_alarm_reg);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
				&vp_reg->srpcim_to_vpath_alarm_reg);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
				&vp_reg->vpath_ppif_int_status);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
				&vp_reg->srpcim_msg_to_vpath_reg);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
				&vp_reg->vpath_pcipif_int_status);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
				&vp_reg->prc_alarm_reg);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
				&vp_reg->wrdma_alarm_status);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
				&vp_reg->asic_ntwk_vp_err_reg);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
				&vp_reg->xgmac_vp_int_status);

	readq(&vp_reg->vpath_general_int_status);

	/* Mask unwanted interrupts */
	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
				&vp_reg->vpath_pcipif_int_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
				&vp_reg->srpcim_msg_to_vpath_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
				&vp_reg->srpcim_to_vpath_alarm_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
				&vp_reg->mrpcim_to_vpath_alarm_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
				&vp_reg->pci_config_errors_mask);

	/* Unmask the individual interrupts */
	writeq((u32)vxge_bVALn((VXGE_HW_GENERAL_ERRORS_REG_DBLGEN_FIFO1_OVRFLOW|
		VXGE_HW_GENERAL_ERRORS_REG_DBLGEN_FIFO2_OVRFLOW|
		VXGE_HW_GENERAL_ERRORS_REG_STATSB_DROP_TIMEOUT_REQ|
		VXGE_HW_GENERAL_ERRORS_REG_STATSB_PIF_CHAIN_ERR), 0, 32),
		&vp_reg->general_errors_mask);

	__vxge_hw_pio_mem_write32_upper(
		(u32)vxge_bVALn((VXGE_HW_KDFCCTL_ERRORS_REG_KDFCCTL_FIFO1_OVRWR|
		VXGE_HW_KDFCCTL_ERRORS_REG_KDFCCTL_FIFO2_OVRWR|
		VXGE_HW_KDFCCTL_ERRORS_REG_KDFCCTL_FIFO1_POISON|
		VXGE_HW_KDFCCTL_ERRORS_REG_KDFCCTL_FIFO2_POISON|
		VXGE_HW_KDFCCTL_ERRORS_REG_KDFCCTL_FIFO1_DMA_ERR|
		VXGE_HW_KDFCCTL_ERRORS_REG_KDFCCTL_FIFO2_DMA_ERR), 0, 32),
		&vp_reg->kdfcctl_errors_mask);

	__vxge_hw_pio_mem_write32_upper(0, &vp_reg->vpath_ppif_int_mask);

	__vxge_hw_pio_mem_write32_upper(
		(u32)vxge_bVALn(VXGE_HW_PRC_ALARM_REG_PRC_RING_BUMP, 0, 32),
		&vp_reg->prc_alarm_mask);

	__vxge_hw_pio_mem_write32_upper(0, &vp_reg->wrdma_alarm_mask);
	__vxge_hw_pio_mem_write32_upper(0, &vp_reg->xgmac_vp_int_mask);

	if (vpath->hldev->first_vp_id != vpath->vp_id)
		__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
				&vp_reg->asic_ntwk_vp_err_mask);
	else
		__vxge_hw_pio_mem_write32_upper((u32)vxge_bVALn((
		VXGE_HW_ASIC_NTWK_VP_ERR_REG_XMACJ_NTWK_REAFFIRMED_FAULT|
			VXGE_HW_ASIC_NTWK_VP_ERR_REG_XMACJ_NTWK_REAFFIRMED_OK),
			0, 32), &vp_reg->asic_ntwk_vp_err_mask);

	__vxge_hw_pio_mem_write32_upper(0, &vp_reg->vpath_general_int_mask);
exit:
	return status;

}

/*
 * vxge_hw_vpath_intr_disable - Disable vpath interrupts.
 * @vpath: Virtual Path handle.
 *
 * Disable vpath interrupts. The function is to be executed the last in
 * vpath initialization sequence.
 *
 * See also: vxge_hw_vpath_intr_enable()
 */
enum vxge_hw_status
vxge_hw_vpath_intr_disable(struct __vxge_hw_virtualpath *vpath)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_hw_vpath_reg __iomem *vp_reg;

	if (vpath->vp_open == VXGE_HW_VP_NOT_OPEN) {
		status = VXGE_HW_ERR_VPATH_NOT_OPEN;
		goto exit;
	}
	vp_reg = vpath->vp_reg;

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->vpath_general_int_mask);

	writeq(VXGE_HW_INTR_MASK_ALL, &vp_reg->kdfcctl_errors_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->general_errors_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->pci_config_errors_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->mrpcim_to_vpath_alarm_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->srpcim_to_vpath_alarm_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->vpath_ppif_int_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->srpcim_msg_to_vpath_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->vpath_pcipif_int_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->wrdma_alarm_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->prc_alarm_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->xgmac_vp_int_mask);

	__vxge_hw_pio_mem_write32_upper((u32)VXGE_HW_INTR_MASK_ALL,
			&vp_reg->asic_ntwk_vp_err_mask);

exit:
	return status;
}

/**
 * vxge_hw_device_mask_all - Mask all device interrupts.
 * @hldev: HW device handle.
 *
 * Mask all device interrupts.
 *
 * See also: vxge_hw_device_unmask_all()
 */
void vxge_hw_device_mask_all(struct __vxge_hw_device *hldev)
{
	u64 val64;

	val64 = VXGE_HW_TITAN_MASK_ALL_INT_ALARM |
			VXGE_HW_TITAN_MASK_ALL_INT_TRAFFIC;

	__vxge_hw_pio_mem_write32_upper((u32)vxge_bVALn(val64, 0, 32),
			&hldev->common_reg->titan_mask_all_int);

	return;
}

/**
 * vxge_hw_device_unmask_all - Unmask all device interrupts.
 * @hldev: HW device handle.
 *
 * Unmask all device interrupts.
 *
 * See also: vxge_hw_device_mask_all()
 */
void vxge_hw_device_unmask_all(struct __vxge_hw_device *hldev)
{
	u64 val64 = VXGE_HW_TITAN_MASK_ALL_INT_TRAFFIC;

	__vxge_hw_pio_mem_write32_upper((u32)vxge_bVALn(val64, 0, 32),
			&hldev->common_reg->titan_mask_all_int);

	return;
}

/**
 * vxge_hw_device_intr_enable - Enable interrupts.
 * @hldev: HW device handle.
 *
 * Enable Titan interrupts. The function is to be executed the last in
 * Titan initialization sequence.
 *
 * See also: vxge_hw_device_intr_disable()
 */
void vxge_hw_device_intr_enable(struct __vxge_hw_device *hldev)
{
	u64 val64;
	u32 val32;

	vxge_hw_device_mask_all(hldev);

	vxge_hw_vpath_intr_enable(&hldev->virtual_path);

	val64 = hldev->tim_int_mask0[VXGE_HW_VPATH_INTR_TX] |
			hldev->tim_int_mask0[VXGE_HW_VPATH_INTR_RX];

	if (val64 != 0) {
		writeq(val64, &hldev->common_reg->tim_int_status0);

		writeq(~val64, &hldev->common_reg->tim_int_mask0);
	}

	val32 = hldev->tim_int_mask1[VXGE_HW_VPATH_INTR_TX] |
			hldev->tim_int_mask1[VXGE_HW_VPATH_INTR_RX];

	if (val32 != 0) {
		__vxge_hw_pio_mem_write32_upper(val32,
				&hldev->common_reg->tim_int_status1);

		__vxge_hw_pio_mem_write32_upper(~val32,
				&hldev->common_reg->tim_int_mask1);
	}

	val64 = readq(&hldev->common_reg->titan_general_int_status);

	/* We have not enabled the top level interrupt yet.
	 * This will be controlled from vxge_irq() entry api.
	 */
	return;
}

/**
 * vxge_hw_device_intr_disable - Disable Titan interrupts.
 * @hldev: HW device handle.
 *
 * Disable Titan interrupts.
 *
 * See also: vxge_hw_device_intr_enable()
 */
void vxge_hw_device_intr_disable(struct __vxge_hw_device *hldev)
{
	vxge_hw_device_mask_all(hldev);

	/* mask all the tim interrupts */
	writeq(VXGE_HW_INTR_MASK_ALL, &hldev->common_reg->tim_int_mask0);
	__vxge_hw_pio_mem_write32_upper(VXGE_HW_DEFAULT_32,
				&hldev->common_reg->tim_int_mask1);

	vxge_hw_vpath_intr_disable(&hldev->virtual_path);

	return;
}

/**
 * vxge_hw_ring_rxd_post - Post descriptor on the ring.
 * @ring: Handle to the ring object used for receive
 * @rxdh: Descriptor obtained via vxge_hw_ring_rxd_reserve().
 *
 * Post	descriptor on the ring.
 * Prior to posting the	descriptor should be filled in accordance with
 * Host/Titan interface specification for a given service (LL, etc.).
 */
void vxge_hw_ring_rxd_post(struct __vxge_hw_ring *ring __unused,
				struct vxge_hw_ring_rxd_1 *rxdp)
{
	rxdp->control_0 = VXGE_HW_RING_RXD_LIST_OWN_ADAPTER;
}

/**
 * __vxge_hw_non_offload_db_post - Post non offload doorbell
 *
 * @fifo: fifohandle
 * @txdl_ptr: The starting location of the TxDL in host memory
 * @num_txds: The highest TxD in this TxDL (0 to 255 means 1 to 256)
 *
 * This function posts a non-offload doorbell to doorbell FIFO
 *
 */
static void __vxge_hw_non_offload_db_post(struct __vxge_hw_fifo *fifo,
	u64 txdl_ptr, u32 num_txds)
{
	writeq(VXGE_HW_NODBW_TYPE(VXGE_HW_NODBW_TYPE_NODBW) |
		VXGE_HW_NODBW_LAST_TXD_NUMBER(num_txds),
		&fifo->nofl_db->control_0);

	wmb();

	writeq(txdl_ptr, &fifo->nofl_db->txdl_ptr);

	wmb();
}

/**
 * vxge_hw_fifo_free_txdl_get: fetch next available txd in the fifo
 *
 * @fifo: tx channel handle
 */
struct vxge_hw_fifo_txd *
	vxge_hw_fifo_free_txdl_get(struct __vxge_hw_fifo *fifo)
{
	struct vxge_hw_fifo_txd *txdp;

	txdp = fifo->txdl + fifo->sw_offset;
	if (txdp->control_0 & VXGE_HW_FIFO_TXD_LIST_OWN_ADAPTER) {
		vxge_debug(VXGE_ERR, "%s:%d, error: txd(%d) owned by hw\n",
				__func__, __LINE__, fifo->sw_offset);
		return NULL;
	}

	return txdp;
}
/**
 * vxge_hw_fifo_txdl_buffer_set - Set transmit buffer pointer in the
 * descriptor.
 * @fifo: Handle to the fifo object used for non offload send
 * @txdlh: Descriptor handle.
 * @iob: data buffer.
 */
void vxge_hw_fifo_txdl_buffer_set(struct __vxge_hw_fifo *fifo,
			struct vxge_hw_fifo_txd *txdp,
			struct io_buffer *iob)
{
	txdp->control_0 = VXGE_HW_FIFO_TXD_GATHER_CODE(
			VXGE_HW_FIFO_GATHER_CODE_FIRST_LAST);
	txdp->control_0 |= VXGE_HW_FIFO_TXD_BUFFER_SIZE(iob_len(iob));

	txdp->control_1 = VXGE_HW_FIFO_TXD_INT_NUMBER(fifo->tx_intr_num);
	txdp->control_1 |= VXGE_HW_FIFO_TXD_INT_TYPE_PER_LIST;

	txdp->host_control = (intptr_t)iob;
	txdp->buffer_pointer = virt_to_bus(iob->data);
}

/**
 * vxge_hw_fifo_txdl_post - Post descriptor on the fifo channel.
 * @fifo: Handle to the fifo object used for non offload send
 * @txdp: Tx Descriptor
 *
 * Post descriptor on the 'fifo' type channel for transmission.
 * Prior to posting the descriptor should be filled in accordance with
 * Host/Titan interface specification for a given service (LL, etc.).
 *
 */
void vxge_hw_fifo_txdl_post(struct __vxge_hw_fifo *fifo,
			struct vxge_hw_fifo_txd *txdp)
{
	txdp->control_0 |= VXGE_HW_FIFO_TXD_LIST_OWN_ADAPTER;

	__vxge_hw_non_offload_db_post(fifo, (u64) virt_to_bus(txdp), 0);

	vxge_hw_fifo_txd_offset_up(&fifo->sw_offset);
}

/*
 * __vxge_hw_vpath_alarm_process - Process Alarms.
 * @vpath: Virtual Path.
 * @skip_alarms: Do not clear the alarms
 *
 * Process vpath alarms.
 *
 */
static enum vxge_hw_status __vxge_hw_vpath_alarm_process(
			struct __vxge_hw_virtualpath *vpath)
{
	u64 val64;
	u64 alarm_status;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_device *hldev = NULL;
	struct vxge_hw_vpath_reg *vp_reg;

	hldev = vpath->hldev;
	vp_reg = vpath->vp_reg;
	alarm_status = readq(&vp_reg->vpath_general_int_status);

	if (alarm_status == VXGE_HW_ALL_FOXES) {

		vxge_debug(VXGE_ERR, "%s: %s:%d, slot freeze error\n",
			hldev->ndev->name, __func__, __LINE__);
		status = VXGE_HW_ERR_SLOT_FREEZE;
		goto out;
	}

	if (alarm_status & ~(
		VXGE_HW_VPATH_GENERAL_INT_STATUS_PIC_INT |
		VXGE_HW_VPATH_GENERAL_INT_STATUS_PCI_INT |
		VXGE_HW_VPATH_GENERAL_INT_STATUS_WRDMA_INT |
		VXGE_HW_VPATH_GENERAL_INT_STATUS_XMAC_INT)) {

		vxge_debug(VXGE_ERR, "%s: %s:%d, Unknown vpath alarm\n",
			hldev->ndev->name, __func__, __LINE__);
		status = VXGE_HW_FAIL;
		goto out;
	}

	if (alarm_status & VXGE_HW_VPATH_GENERAL_INT_STATUS_XMAC_INT) {

		val64 = readq(&vp_reg->xgmac_vp_int_status);

		if (val64 &
		VXGE_HW_XGMAC_VP_INT_STATUS_ASIC_NTWK_VP_ERR_ASIC_NTWK_VP_INT) {

			val64 = readq(&vp_reg->asic_ntwk_vp_err_reg);

			if (((val64 &
				VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_FLT) &&
			    (!(val64 &
				VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_OK))) ||
			    ((val64 &
				VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_FLT_OCCURR)
				&& (!(val64 &
				VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_OK_OCCURR)
			))) {
				writeq(VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_FLT,
					&vp_reg->asic_ntwk_vp_err_mask);

				netdev_link_down(hldev->ndev);
				vxge_debug(VXGE_INTR, "%s: %s:%d link down\n",
					hldev->ndev->name, __func__, __LINE__);
			}

			if (((val64 &
				VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_OK) &&
			    (!(val64 &
				VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_FLT))) ||
			    ((val64 &
				VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_OK_OCCURR)
				&& (!(val64 &
				VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_FLT_OCCURR)
			))) {
				writeq(VXGE_HW_ASIC_NW_VP_ERR_REG_XMACJ_STN_OK,
					&vp_reg->asic_ntwk_vp_err_mask);

				netdev_link_up(hldev->ndev);
				vxge_debug(VXGE_INTR, "%s: %s:%d link up\n",
					hldev->ndev->name, __func__, __LINE__);
			}

			writeq(VXGE_HW_INTR_MASK_ALL,
				&vp_reg->asic_ntwk_vp_err_reg);
		}
	} else {
		vxge_debug(VXGE_INFO, "%s: %s:%d unhandled alarm %llx\n",
				hldev->ndev->name, __func__, __LINE__,
				alarm_status);
	}
out:
	return status;
}

/**
 * vxge_hw_device_clear_tx_rx - Acknowledge (that is, clear) the
 * condition that has caused the Tx and RX interrupt.
 * @hldev: HW device.
 *
 * Acknowledge (that is, clear) the condition that has caused
 * the Tx and Rx interrupt.
 * See also: vxge_hw_device_begin_irq(),
 * vxge_hw_device_mask_tx_rx(), vxge_hw_device_unmask_tx_rx().
 */
void vxge_hw_device_clear_tx_rx(struct __vxge_hw_device *hldev)
{

	if ((hldev->tim_int_mask0[VXGE_HW_VPATH_INTR_TX] != 0) ||
			(hldev->tim_int_mask0[VXGE_HW_VPATH_INTR_RX] != 0)) {
		writeq((hldev->tim_int_mask0[VXGE_HW_VPATH_INTR_TX] |
			hldev->tim_int_mask0[VXGE_HW_VPATH_INTR_RX]),
			&hldev->common_reg->tim_int_status0);
	}

	if ((hldev->tim_int_mask1[VXGE_HW_VPATH_INTR_TX] != 0) ||
			(hldev->tim_int_mask1[VXGE_HW_VPATH_INTR_RX] != 0)) {
		__vxge_hw_pio_mem_write32_upper(
			(hldev->tim_int_mask1[VXGE_HW_VPATH_INTR_TX] |
			hldev->tim_int_mask1[VXGE_HW_VPATH_INTR_RX]),
			&hldev->common_reg->tim_int_status1);
	}

	return;
}


/**
 * vxge_hw_device_begin_irq - Begin IRQ processing.
 * @hldev: HW device handle.
 *
 * The function performs two actions, It first checks whether (shared IRQ) the
 * interrupt was raised by the device. Next, it masks the device interrupts.
 *
 * Note:
 * vxge_hw_device_begin_irq() does not flush MMIO writes through the
 * bridge. Therefore, two back-to-back interrupts are potentially possible.
 *
 * Returns: 0, if the interrupt is not "ours" (note that in this case the
 * device remain enabled).
 * Otherwise, vxge_hw_device_begin_irq() returns 64bit general adapter
 * status.
 */
enum vxge_hw_status
vxge_hw_device_begin_irq(struct __vxge_hw_device *hldev)
{
	u64 val64;
	u64 adapter_status;
	u64 vpath_mask;
	enum vxge_hw_status ret = VXGE_HW_OK;

	val64 = readq(&hldev->common_reg->titan_general_int_status);

	if (!val64) {
		ret = VXGE_HW_ERR_WRONG_IRQ;
		goto exit;
	}

	if (val64 == VXGE_HW_ALL_FOXES) {

		adapter_status = readq(&hldev->common_reg->adapter_status);

		if (adapter_status == VXGE_HW_ALL_FOXES) {

			vxge_debug(VXGE_ERR, "%s: %s:%d critical error "
				"occurred\n", hldev->ndev->name,
				__func__, __LINE__);
			ret = VXGE_HW_ERR_SLOT_FREEZE;
			goto exit;
		}
	}

	vpath_mask = hldev->vpaths_deployed >>
				(64 - VXGE_HW_MAX_VIRTUAL_PATHS);
	if (val64 & VXGE_HW_TITAN_GENERAL_INT_STATUS_VPATH_TRAFFIC_INT(
				vpath_mask))
		vxge_hw_device_clear_tx_rx(hldev);

	if (val64 & VXGE_HW_TITAN_GENERAL_INT_STATUS_VPATH_ALARM_INT)
		ret = __vxge_hw_vpath_alarm_process(&hldev->virtual_path);

exit:
	return ret;
}

/**
 * vxge_hw_vpath_doorbell_rx - Indicates to hw the qwords of receive
 * descriptors posted.
 * @ring: Handle to the ring object used for receive
 *
 * The function writes the number of qwords of rxds posted during replishment.
 * Since the function is called frequently, a flush is not required to post the
 * write transaction. At the very least, the previous write will be flushed
 * once the subsequent write is made.
 *
 * Returns: None.
 */
void vxge_hw_vpath_doorbell_rx(struct __vxge_hw_ring *ring)
{
	u32 rxds_qw_per_block = VXGE_HW_MAX_RXDS_PER_BLOCK_1 *
		VXGE_HW_RING_RXD_QWORDS_MODE_1;

	ring->doorbell_cnt += VXGE_HW_RING_RXD_QWORDS_MODE_1;

	ring->total_db_cnt += VXGE_HW_RING_RXD_QWORDS_MODE_1;

	if (ring->total_db_cnt >= rxds_qw_per_block) {
		/* For each block add 4 more qwords */
		ring->doorbell_cnt += VXGE_HW_RING_RXD_QWORDS_MODE_1;

		/* Reset total count */
		ring->total_db_cnt -= rxds_qw_per_block;
	}

	if (ring->doorbell_cnt >= ring->rxd_qword_limit) {
		wmb();
		writeq(VXGE_HW_PRC_RXD_DOORBELL_NEW_QW_CNT(
			ring->doorbell_cnt),
			&ring->vp_reg->prc_rxd_doorbell);
		ring->doorbell_cnt = 0;
	}
}

/**
 * vxge_hw_vpath_poll_rx - Poll Rx Virtual Path for completed
 * descriptors and process the same.
 * @ring: Handle to the ring object used for receive
 *
 * The function	polls the Rx for the completed	descriptors.
 */
#define ETH_FCS_LEN	4
enum vxge_hw_status vxge_hw_vpath_poll_rx(struct __vxge_hw_ring *ring)
{
	struct __vxge_hw_device *hldev;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_hw_ring_rxd_1 *rxd;
	unsigned int len;
	enum vxge_hw_ring_tcode tcode;
	struct io_buffer *rx_iob, *iobuf = NULL;
	u16 poll_count = 0;

	hldev = ring->vpathh->hldev;

	do {
		rxd = &ring->rxdl->rxd[ring->rxd_offset];
		tcode = VXGE_HW_RING_RXD_T_CODE_GET(rxd->control_0);

		/* if tcode is VXGE_HW_RING_T_CODE_FRM_DROP, it is
		 * possible the ownership bit still set to adapter
		 */
		if ((rxd->control_0 & VXGE_HW_RING_RXD_LIST_OWN_ADAPTER)
			&& (tcode == VXGE_HW_RING_T_CODE_OK)) {

			status = VXGE_HW_INF_NO_MORE_COMPLETED_DESCRIPTORS;
			goto err0;
		}

		vxge_debug(VXGE_INFO, "%s: rx frame received at offset %d\n",
			hldev->ndev->name, ring->rxd_offset);

		if (tcode != VXGE_HW_RING_T_CODE_OK) {
			netdev_rx_err(hldev->ndev, NULL, -EINVAL);
			vxge_debug(VXGE_ERR, "%s:%d, rx error tcode %d\n",
				__func__, __LINE__, tcode);
			status = VXGE_HW_FAIL;
			goto err1;
		}

		iobuf = (struct io_buffer *)(intptr_t)rxd->host_control;

		len = VXGE_HW_RING_RXD_1_BUFFER0_SIZE_GET(rxd->control_1);
		len -= ETH_FCS_LEN;

		rx_iob = alloc_iob(len);
		if (!rx_iob) {
			netdev_rx_err(hldev->ndev, NULL, -ENOMEM);
			vxge_debug(VXGE_ERR, "%s:%d, alloc_iob error\n",
				__func__, __LINE__);
			status = VXGE_HW_ERR_OUT_OF_MEMORY;
			goto err1;
		}

		memcpy(iob_put(rx_iob, len), iobuf->data, len);
		/* Add this packet to the receive queue. */
		netdev_rx(hldev->ndev, rx_iob);

err1:
		/* repost the rxd */
		rxd->control_0 = rxd->control_1 = 0;
		vxge_hw_ring_rxd_1b_set(rxd, iobuf,
				VXGE_LL_MAX_FRAME_SIZE(hldev->vdev));
		vxge_hw_ring_rxd_post(ring, rxd);

		/* repost the qword count for doorbell */
		vxge_hw_vpath_doorbell_rx(ring);

		/* increment the descriptor offset */
		vxge_hw_ring_rxd_offset_up(&ring->rxd_offset);

	} while (++poll_count < ring->rx_poll_weight);
err0:
	return status;
}

/**
 * vxge_hw_vpath_poll_tx - Poll Tx for completed descriptors and process
 * the same.
 * @fifo: Handle to the fifo object used for non offload send
 *
 * The function	polls the Tx for the completed	descriptors and	calls
 * the driver via supplied completion callback.
 */
enum vxge_hw_status vxge_hw_vpath_poll_tx(struct __vxge_hw_fifo *fifo)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_hw_fifo_txd *txdp;

	txdp = fifo->txdl + fifo->hw_offset;
	if (!(txdp->control_0 & VXGE_HW_FIFO_TXD_LIST_OWN_ADAPTER)
		&& (txdp->host_control)) {

		vxge_xmit_compl(fifo, txdp,
			VXGE_HW_FIFO_TXD_T_CODE_GET(txdp->control_0));

		vxge_hw_fifo_txd_offset_up(&fifo->hw_offset);
	}

	return status;
}
