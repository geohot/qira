/*
 * vxge-config.c: iPXE driver for Neterion Inc's X3100 Series 10GbE PCIe I/O
 *              Virtualized Server Adapter.
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

#include <stdlib.h>
#include <stdio.h>
#include <ipxe/malloc.h>
#include <ipxe/pci.h>
#include <ipxe/iobuf.h>
#include <ipxe/ethernet.h>
#include <byteswap.h>

#include "vxge_traffic.h"
#include "vxge_config.h"
#include "vxge_main.h"

void
vxge_hw_vpath_set_zero_rx_frm_len(struct __vxge_hw_device *hldev)
{
	u64 val64;
	struct __vxge_hw_virtualpath *vpath;
	struct vxge_hw_vpath_reg __iomem *vp_reg;

	vpath = &hldev->virtual_path;
	vp_reg = vpath->vp_reg;

	val64 = readq(&vp_reg->rxmac_vcfg0);
	val64 &= ~VXGE_HW_RXMAC_VCFG0_RTS_MAX_FRM_LEN(0x3fff);
	writeq(val64, &vp_reg->rxmac_vcfg0);
	val64 = readq(&vp_reg->rxmac_vcfg0);
	return;
}

enum vxge_hw_status
vxge_hw_set_fw_api(struct __vxge_hw_device *hldev,
		u64 vp_id,
		u32 action,
		u32 offset,
		u64 data0,
		u64 data1)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	u64 val64;
	u32 fw_memo = VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO;

	struct vxge_hw_vpath_reg __iomem *vp_reg;

	vp_reg = (struct vxge_hw_vpath_reg __iomem *)hldev->vpath_reg[vp_id];

	writeq(data0, &vp_reg->rts_access_steer_data0);
	writeq(data1, &vp_reg->rts_access_steer_data1);

	wmb();

	val64 = VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION(action) |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL(fw_memo) |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_OFFSET(offset) |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE;

	writeq(val64, &vp_reg->rts_access_steer_ctrl);

	wmb();

	status = __vxge_hw_device_register_poll(
			&vp_reg->rts_access_steer_ctrl,
			VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE,
			WAIT_FACTOR *
			VXGE_HW_DEF_DEVICE_POLL_MILLIS);

	if (status != VXGE_HW_OK)
		return VXGE_HW_FAIL;

	val64 = readq(&vp_reg->rts_access_steer_ctrl);

	if (val64 & VXGE_HW_RTS_ACCESS_STEER_CTRL_RMACJ_STATUS)
		status = VXGE_HW_OK;
	else
		status = VXGE_HW_FAIL;

	return status;
}

/* Get function mode */
enum vxge_hw_status
vxge_hw_get_func_mode(struct __vxge_hw_device *hldev, u32 *func_mode)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_hw_vpath_reg __iomem *vp_reg;
	u64 val64;
	int vp_id;

	/* get the first vpath number assigned to this function */
	vp_id = hldev->first_vp_id;

	vp_reg = (struct vxge_hw_vpath_reg __iomem *)hldev->vpath_reg[vp_id];

	status = vxge_hw_set_fw_api(hldev, vp_id,
				VXGE_HW_FW_API_GET_FUNC_MODE, 0, 0, 0);

	if (status == VXGE_HW_OK) {
		val64 = readq(&vp_reg->rts_access_steer_data0);
		*func_mode = VXGE_HW_GET_FUNC_MODE_VAL(val64);
	}

	return status;
}

/*
 * __vxge_hw_device_pci_e_init
 * Initialize certain PCI/PCI-X configuration registers
 * with recommended values. Save config space for future hw resets.
 */
void
__vxge_hw_device_pci_e_init(struct __vxge_hw_device *hldev)
{
	u16 cmd = 0;
	struct pci_device *pdev = hldev->pdev;

	vxge_trace();

	/* Set the PErr Repconse bit and SERR in PCI command register. */
	pci_read_config_word(pdev, PCI_COMMAND, &cmd);
	cmd |= 0x140;
	pci_write_config_word(pdev, PCI_COMMAND, cmd);

	return;
}

/*
 * __vxge_hw_device_register_poll
 * Will poll certain register for specified amount of time.
 * Will poll until masked bit is not cleared.
 */
enum vxge_hw_status
__vxge_hw_device_register_poll(void __iomem *reg, u64 mask, u32 max_millis)
{
	u64 val64;
	u32 i = 0;
	enum vxge_hw_status ret = VXGE_HW_FAIL;

	udelay(10);

	do {
		val64 = readq(reg);
		if (!(val64 & mask))
			return VXGE_HW_OK;
		udelay(100);
	} while (++i <= 9);

	i = 0;
	do {
		val64 = readq(reg);
		if (!(val64 & mask))
			return VXGE_HW_OK;
		udelay(1000);
	} while (++i <= max_millis);

	return ret;
}

 /* __vxge_hw_device_vpath_reset_in_prog_check - Check if vpath reset
 * in progress
 * This routine checks the vpath reset in progress register is turned zero
 */
enum vxge_hw_status
__vxge_hw_device_vpath_reset_in_prog_check(u64 __iomem *vpath_rst_in_prog)
{
	enum vxge_hw_status status;

	vxge_trace();

	status = __vxge_hw_device_register_poll(vpath_rst_in_prog,
			VXGE_HW_VPATH_RST_IN_PROG_VPATH_RST_IN_PROG(0x1ffff),
			VXGE_HW_DEF_DEVICE_POLL_MILLIS);
	return status;
}

/*
 * __vxge_hw_device_get_legacy_reg
 * This routine gets the legacy register section's memory mapped address
 * and sets the swapper.
 */
static struct vxge_hw_legacy_reg __iomem *
__vxge_hw_device_get_legacy_reg(struct pci_device *pdev, void __iomem *bar0)
{
	enum vxge_hw_status status;
	struct vxge_hw_legacy_reg __iomem *legacy_reg;
	/*
	 * If the length of Bar0 is 16MB, then assume that we are configured
	 * in MF8P_VP2 mode and then add 8MB to the legacy_reg offsets
	 */
	if (pci_bar_size(pdev, PCI_BASE_ADDRESS_0) == 0x1000000)
		legacy_reg = (struct vxge_hw_legacy_reg __iomem *)
				(bar0 + 0x800000);
	else
		legacy_reg = (struct vxge_hw_legacy_reg __iomem *)bar0;

	status = __vxge_hw_legacy_swapper_set(legacy_reg);
	if (status != VXGE_HW_OK)
		return NULL;

	return legacy_reg;
}
/*
 * __vxge_hw_device_toc_get
 * This routine sets the swapper and reads the toc pointer and returns the
 * memory mapped address of the toc
 */
struct vxge_hw_toc_reg __iomem *
__vxge_hw_device_toc_get(void __iomem *bar0,
	struct vxge_hw_legacy_reg __iomem *legacy_reg)
{
	u64 val64;
	struct vxge_hw_toc_reg __iomem *toc = NULL;

	val64 =	readq(&legacy_reg->toc_first_pointer);
	toc = (struct vxge_hw_toc_reg __iomem *)(bar0+val64);

	return toc;
}

/*
 * __vxge_hw_device_reg_addr_get
 * This routine sets the swapper and reads the toc pointer and initializes the
 * register location pointers in the device object. It waits until the ric is
 * completed initializing registers.
 */
enum vxge_hw_status
__vxge_hw_device_reg_addr_get(struct __vxge_hw_device *hldev)
{
	u64 val64;
	u32 i;
	enum vxge_hw_status status = VXGE_HW_OK;

	hldev->legacy_reg = __vxge_hw_device_get_legacy_reg(hldev->pdev,
					hldev->bar0);
	if (hldev->legacy_reg  == NULL) {
		status = VXGE_HW_FAIL;
		goto exit;
	}

	hldev->toc_reg = __vxge_hw_device_toc_get(hldev->bar0,
					hldev->legacy_reg);
	if (hldev->toc_reg  == NULL) {
		status = VXGE_HW_FAIL;
		goto exit;
	}

	val64 = readq(&hldev->toc_reg->toc_common_pointer);
	hldev->common_reg =
		(struct vxge_hw_common_reg __iomem *)(hldev->bar0 + val64);

	val64 = readq(&hldev->toc_reg->toc_mrpcim_pointer);
	hldev->mrpcim_reg =
		(struct vxge_hw_mrpcim_reg __iomem *)(hldev->bar0 + val64);

	for (i = 0; i < VXGE_HW_TITAN_SRPCIM_REG_SPACES; i++) {
		val64 = readq(&hldev->toc_reg->toc_srpcim_pointer[i]);
		hldev->srpcim_reg[i] =
			(struct vxge_hw_srpcim_reg __iomem *)
				(hldev->bar0 + val64);
	}

	for (i = 0; i < VXGE_HW_TITAN_VPMGMT_REG_SPACES; i++) {
		val64 = readq(&hldev->toc_reg->toc_vpmgmt_pointer[i]);
		hldev->vpmgmt_reg[i] =
		(struct vxge_hw_vpmgmt_reg __iomem *)(hldev->bar0 + val64);
	}

	for (i = 0; i < VXGE_HW_TITAN_VPATH_REG_SPACES; i++) {
		val64 = readq(&hldev->toc_reg->toc_vpath_pointer[i]);
		hldev->vpath_reg[i] =
			(struct vxge_hw_vpath_reg __iomem *)
				(hldev->bar0 + val64);
	}

	val64 = readq(&hldev->toc_reg->toc_kdfc);

	switch (VXGE_HW_TOC_GET_KDFC_INITIAL_BIR(val64)) {
	case 0:
		hldev->kdfc = (u8 __iomem *)(hldev->bar0 +
			VXGE_HW_TOC_GET_KDFC_INITIAL_OFFSET(val64));
		break;
	default:
		break;
	}

	status = __vxge_hw_device_vpath_reset_in_prog_check(
			(u64 __iomem *)&hldev->common_reg->vpath_rst_in_prog);
exit:
	return status;
}

/*
 * __vxge_hw_device_access_rights_get: Get Access Rights of the driver
 * This routine returns the Access Rights of the driver
 */
static u32
__vxge_hw_device_access_rights_get(u32 host_type, u32 func_id)
{
	u32 access_rights = VXGE_HW_DEVICE_ACCESS_RIGHT_VPATH;

	switch (host_type) {
	case VXGE_HW_NO_MR_NO_SR_NORMAL_FUNCTION:
		if (func_id == 0) {
			access_rights |= VXGE_HW_DEVICE_ACCESS_RIGHT_MRPCIM |
					VXGE_HW_DEVICE_ACCESS_RIGHT_SRPCIM;
		}
		break;
	case VXGE_HW_MR_NO_SR_VH0_BASE_FUNCTION:
		access_rights |= VXGE_HW_DEVICE_ACCESS_RIGHT_MRPCIM |
				VXGE_HW_DEVICE_ACCESS_RIGHT_SRPCIM;
		break;
	case VXGE_HW_NO_MR_SR_VH0_FUNCTION0:
		access_rights |= VXGE_HW_DEVICE_ACCESS_RIGHT_MRPCIM |
				VXGE_HW_DEVICE_ACCESS_RIGHT_SRPCIM;
		break;
	case VXGE_HW_NO_MR_SR_VH0_VIRTUAL_FUNCTION:
	case VXGE_HW_SR_VH_VIRTUAL_FUNCTION:
	case VXGE_HW_MR_SR_VH0_INVALID_CONFIG:
		break;
	case VXGE_HW_SR_VH_FUNCTION0:
	case VXGE_HW_VH_NORMAL_FUNCTION:
		access_rights |= VXGE_HW_DEVICE_ACCESS_RIGHT_SRPCIM;
		break;
	}

	return access_rights;
}

/*
 * __vxge_hw_device_host_info_get
 * This routine returns the host type assignments
 */
void __vxge_hw_device_host_info_get(struct __vxge_hw_device *hldev)
{
	u64 val64;
	u32 i;

	val64 = readq(&hldev->common_reg->host_type_assignments);

	hldev->host_type =
	   (u32)VXGE_HW_HOST_TYPE_ASSIGNMENTS_GET_HOST_TYPE_ASSIGNMENTS(val64);

	hldev->vpath_assignments = readq(&hldev->common_reg->vpath_assignments);

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {

		if (!(hldev->vpath_assignments & vxge_mBIT(i)))
			continue;

		hldev->func_id =
			__vxge_hw_vpath_func_id_get(hldev->vpmgmt_reg[i]);

		hldev->access_rights = __vxge_hw_device_access_rights_get(
			hldev->host_type, hldev->func_id);

		hldev->first_vp_id = i;
		break;
	}

	return;
}

/**
 * vxge_hw_device_hw_info_get - Get the hw information
 * Returns the vpath mask that has the bits set for each vpath allocated
 * for the driver, FW version information and the first mac addresse for
 * each vpath
 */
enum vxge_hw_status
vxge_hw_device_hw_info_get(struct pci_device *pdev, void __iomem *bar0,
				struct vxge_hw_device_hw_info *hw_info)
{
	u32 i;
	u64 val64;
	struct vxge_hw_toc_reg __iomem *toc;
	struct vxge_hw_mrpcim_reg __iomem *mrpcim_reg;
	struct vxge_hw_common_reg __iomem *common_reg;
	struct vxge_hw_vpath_reg __iomem *vpath_reg;
	struct vxge_hw_vpmgmt_reg __iomem *vpmgmt_reg;
	struct vxge_hw_legacy_reg __iomem *legacy_reg;
	enum vxge_hw_status status;

	vxge_trace();

	memset(hw_info, 0, sizeof(struct vxge_hw_device_hw_info));

	legacy_reg = __vxge_hw_device_get_legacy_reg(pdev, bar0);
	if (legacy_reg == NULL) {
		status = VXGE_HW_ERR_CRITICAL;
		goto exit;
	}

	toc = __vxge_hw_device_toc_get(bar0, legacy_reg);
	if (toc == NULL) {
		status = VXGE_HW_ERR_CRITICAL;
		goto exit;
	}

	val64 = readq(&toc->toc_common_pointer);
	common_reg = (struct vxge_hw_common_reg __iomem *)(bar0 + val64);

	status = __vxge_hw_device_vpath_reset_in_prog_check(
		(u64 __iomem *)&common_reg->vpath_rst_in_prog);
	if (status != VXGE_HW_OK)
		goto exit;

	hw_info->vpath_mask = readq(&common_reg->vpath_assignments);

	val64 = readq(&common_reg->host_type_assignments);

	hw_info->host_type =
	   (u32)VXGE_HW_HOST_TYPE_ASSIGNMENTS_GET_HOST_TYPE_ASSIGNMENTS(val64);

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {

		if (!((hw_info->vpath_mask) & vxge_mBIT(i)))
			continue;

		val64 = readq(&toc->toc_vpmgmt_pointer[i]);

		vpmgmt_reg = (struct vxge_hw_vpmgmt_reg __iomem *)
				(bar0 + val64);

		hw_info->func_id = __vxge_hw_vpath_func_id_get(vpmgmt_reg);
		if (__vxge_hw_device_access_rights_get(hw_info->host_type,
			hw_info->func_id) &
			VXGE_HW_DEVICE_ACCESS_RIGHT_MRPCIM) {

			val64 = readq(&toc->toc_mrpcim_pointer);

			mrpcim_reg = (struct vxge_hw_mrpcim_reg __iomem *)
					(bar0 + val64);

			writeq(0, &mrpcim_reg->xgmac_gen_fw_memo_mask);
			wmb();
		}

		val64 = readq(&toc->toc_vpath_pointer[i]);

		vpath_reg = (struct vxge_hw_vpath_reg __iomem *)(bar0 + val64);

		status = __vxge_hw_vpath_fw_ver_get(vpath_reg, hw_info);
		if (status != VXGE_HW_OK)
			goto exit;

		status = __vxge_hw_vpath_card_info_get(vpath_reg, hw_info);
		if (status != VXGE_HW_OK)
			goto exit;

		break;
	}

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {

		if (!((hw_info->vpath_mask) & vxge_mBIT(i)))
			continue;

		val64 = readq(&toc->toc_vpath_pointer[i]);
		vpath_reg = (struct vxge_hw_vpath_reg __iomem *)(bar0 + val64);

		status =  __vxge_hw_vpath_addr_get(vpath_reg,
				hw_info->mac_addrs[i],
				hw_info->mac_addr_masks[i]);
		if (status != VXGE_HW_OK)
			goto exit;
	}
exit:
	return status;
}

/*
 * vxge_hw_device_initialize - Initialize Titan device.
 * Initialize Titan device. Note that all the arguments of this public API
 * are 'IN', including @hldev. Driver cooperates with
 * OS to find new Titan device, locate its PCI and memory spaces.
 *
 * When done, the driver allocates sizeof(struct __vxge_hw_device) bytes for HW
 * to enable the latter to perform Titan hardware initialization.
 */
enum vxge_hw_status
vxge_hw_device_initialize(
	struct __vxge_hw_device **devh,
	void *bar0,
	struct pci_device *pdev,
	u8 titan1)
{
	struct __vxge_hw_device *hldev = NULL;
	enum vxge_hw_status status = VXGE_HW_OK;

	vxge_trace();

	hldev = (struct __vxge_hw_device *)
			zalloc(sizeof(struct __vxge_hw_device));
	if (hldev == NULL) {
		vxge_debug(VXGE_ERR, "hldev allocation failed\n");
		status = VXGE_HW_ERR_OUT_OF_MEMORY;
		goto exit;
	}

	hldev->magic = VXGE_HW_DEVICE_MAGIC;

	hldev->bar0 = bar0;
	hldev->pdev = pdev;
	hldev->titan1 = titan1;

	__vxge_hw_device_pci_e_init(hldev);

	status = __vxge_hw_device_reg_addr_get(hldev);
	if (status != VXGE_HW_OK) {
		vxge_debug(VXGE_ERR, "%s:%d __vxge_hw_device_reg_addr_get "
			"failed\n", __func__, __LINE__);
		vxge_hw_device_terminate(hldev);
		goto exit;
	}

	__vxge_hw_device_host_info_get(hldev);

	*devh = hldev;
exit:
	return status;
}

/*
 * vxge_hw_device_terminate - Terminate Titan device.
 * Terminate HW device.
 */
void
vxge_hw_device_terminate(struct __vxge_hw_device *hldev)
{
	vxge_trace();

	assert(hldev->magic == VXGE_HW_DEVICE_MAGIC);

	hldev->magic = VXGE_HW_DEVICE_DEAD;
	free(hldev);
}

/*
 *vxge_hw_ring_replenish - Initial replenish of RxDs
 * This function replenishes the RxDs from reserve array to work array
 */
enum vxge_hw_status
vxge_hw_ring_replenish(struct __vxge_hw_ring *ring)
{
	struct __vxge_hw_device *hldev;
	struct vxge_hw_ring_rxd_1 *rxd;
	enum vxge_hw_status status = VXGE_HW_OK;
	u8 offset = 0;
	struct __vxge_hw_ring_block *block;
	u8 i, iob_off;

	vxge_trace();

	hldev = ring->vpathh->hldev;
	/*
	 * We allocate all the dma buffers first and then share the
	 * these buffers among the all rx descriptors in the block.
	 */
	for (i = 0; i < ARRAY_SIZE(ring->iobuf); i++) {
		ring->iobuf[i] = alloc_iob(VXGE_LL_MAX_FRAME_SIZE(hldev->vdev));
		if (!ring->iobuf[i]) {
			while (i) {
				free_iob(ring->iobuf[--i]);
				ring->iobuf[i] = NULL;
			}
			status = VXGE_HW_ERR_OUT_OF_MEMORY;
			goto iobuf_err;
		}
	}

	for (offset = 0; offset < VXGE_HW_MAX_RXDS_PER_BLOCK_1; offset++) {

		rxd = &ring->rxdl->rxd[offset];
		if (offset == (VXGE_HW_MAX_RXDS_PER_BLOCK_1 - 1))
			iob_off = VXGE_HW_RING_BUF_PER_BLOCK;
		else
			iob_off = offset % ring->buf_per_block;

		rxd->control_0 = rxd->control_1 = 0;
		vxge_hw_ring_rxd_1b_set(rxd, ring->iobuf[iob_off],
				VXGE_LL_MAX_FRAME_SIZE(hldev->vdev));

		vxge_hw_ring_rxd_post(ring, rxd);
	}
	/* linking the block to itself as we use only one rx block*/
	block = ring->rxdl;
	block->reserved_2_pNext_RxD_block = (unsigned long) block;
	block->pNext_RxD_Blk_physical = (u64)virt_to_bus(block);

	ring->rxd_offset = 0;
iobuf_err:
	return status;
}

/*
 * __vxge_hw_ring_create - Create a Ring
 * This function creates Ring and initializes it.
 *
 */
enum vxge_hw_status
__vxge_hw_ring_create(struct __vxge_hw_virtualpath *vpath,
		      struct __vxge_hw_ring *ring)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_device *hldev;
	u32 vp_id;

	vxge_trace();

	hldev = vpath->hldev;
	vp_id = vpath->vp_id;

	ring->rxdl = malloc_dma(sizeof(struct __vxge_hw_ring_block),
			sizeof(struct __vxge_hw_ring_block));
	if (!ring->rxdl) {
		vxge_debug(VXGE_ERR, "%s:%d malloc_dma error\n",
				__func__, __LINE__);
		status = VXGE_HW_ERR_OUT_OF_MEMORY;
		goto exit;
	}
	ring->rxd_offset = 0;
	ring->vpathh = vpath;
	ring->buf_per_block = VXGE_HW_RING_BUF_PER_BLOCK;
	ring->rx_poll_weight = VXGE_HW_RING_RX_POLL_WEIGHT;
	ring->vp_id = vp_id;
	ring->vp_reg = vpath->vp_reg;
	ring->common_reg = hldev->common_reg;

	ring->rxd_qword_limit = VXGE_HW_RING_RXD_QWORD_LIMIT;

	status = vxge_hw_ring_replenish(ring);
	if (status != VXGE_HW_OK) {
		__vxge_hw_ring_delete(ring);
		goto exit;
	}
exit:
	return status;
}

/*
 * __vxge_hw_ring_delete - Removes the ring
 * This function freeup the memory pool and removes the ring
 */
enum vxge_hw_status __vxge_hw_ring_delete(struct __vxge_hw_ring *ring)
{
	u8 i;

	vxge_trace();

	for (i = 0; (i < ARRAY_SIZE(ring->iobuf)) && ring->iobuf[i]; i++) {
		free_iob(ring->iobuf[i]);
		ring->iobuf[i] = NULL;
	}

	if (ring->rxdl) {
		free_dma(ring->rxdl, sizeof(struct __vxge_hw_ring_block));
		ring->rxdl = NULL;
	}
	ring->rxd_offset = 0;

	return VXGE_HW_OK;
}

/*
 * _hw_legacy_swapper_set - Set the swapper bits for the legacy secion.
 * Set the swapper bits appropriately for the legacy section.
 */
enum vxge_hw_status
__vxge_hw_legacy_swapper_set(struct vxge_hw_legacy_reg __iomem *legacy_reg)
{
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;

	vxge_trace();

	val64 = readq(&legacy_reg->toc_swapper_fb);

	wmb();

	switch (val64) {

	case VXGE_HW_SWAPPER_INITIAL_VALUE:
		return status;

	case VXGE_HW_SWAPPER_BYTE_SWAPPED_BIT_FLIPPED:
		writeq(VXGE_HW_SWAPPER_READ_BYTE_SWAP_ENABLE,
			&legacy_reg->pifm_rd_swap_en);
		writeq(VXGE_HW_SWAPPER_READ_BIT_FLAP_ENABLE,
			&legacy_reg->pifm_rd_flip_en);
		writeq(VXGE_HW_SWAPPER_WRITE_BYTE_SWAP_ENABLE,
			&legacy_reg->pifm_wr_swap_en);
		writeq(VXGE_HW_SWAPPER_WRITE_BIT_FLAP_ENABLE,
			&legacy_reg->pifm_wr_flip_en);
		break;

	case VXGE_HW_SWAPPER_BYTE_SWAPPED:
		writeq(VXGE_HW_SWAPPER_READ_BYTE_SWAP_ENABLE,
			&legacy_reg->pifm_rd_swap_en);
		writeq(VXGE_HW_SWAPPER_WRITE_BYTE_SWAP_ENABLE,
			&legacy_reg->pifm_wr_swap_en);
		break;

	case VXGE_HW_SWAPPER_BIT_FLIPPED:
		writeq(VXGE_HW_SWAPPER_READ_BIT_FLAP_ENABLE,
			&legacy_reg->pifm_rd_flip_en);
		writeq(VXGE_HW_SWAPPER_WRITE_BIT_FLAP_ENABLE,
			&legacy_reg->pifm_wr_flip_en);
		break;
	}

	wmb();

	val64 = readq(&legacy_reg->toc_swapper_fb);
	if (val64 != VXGE_HW_SWAPPER_INITIAL_VALUE)
		status = VXGE_HW_ERR_SWAPPER_CTRL;

	return status;
}

/*
 * __vxge_hw_vpath_swapper_set - Set the swapper bits for the vpath.
 * Set the swapper bits appropriately for the vpath.
 */
enum vxge_hw_status
__vxge_hw_vpath_swapper_set(struct vxge_hw_vpath_reg __iomem *vpath_reg)
{
	vxge_trace();

#if (__BYTE_ORDER != __BIG_ENDIAN)
	u64 val64;

	val64 = readq(&vpath_reg->vpath_general_cfg1);
	wmb();
	val64 |= VXGE_HW_VPATH_GENERAL_CFG1_CTL_BYTE_SWAPEN;
	writeq(val64, &vpath_reg->vpath_general_cfg1);
	wmb();
#endif
	return VXGE_HW_OK;
}

/*
 * __vxge_hw_kdfc_swapper_set - Set the swapper bits for the kdfc.
 * Set the swapper bits appropriately for the vpath.
 */
enum vxge_hw_status
__vxge_hw_kdfc_swapper_set(
	struct vxge_hw_legacy_reg __iomem *legacy_reg,
	struct vxge_hw_vpath_reg __iomem *vpath_reg)
{
	u64 val64;

	vxge_trace();

	val64 = readq(&legacy_reg->pifm_wr_swap_en);

	if (val64 == VXGE_HW_SWAPPER_WRITE_BYTE_SWAP_ENABLE) {
		val64 = readq(&vpath_reg->kdfcctl_cfg0);
		wmb();

		val64 |= VXGE_HW_KDFCCTL_CFG0_BYTE_SWAPEN_FIFO0	|
			VXGE_HW_KDFCCTL_CFG0_BYTE_SWAPEN_FIFO1	|
			VXGE_HW_KDFCCTL_CFG0_BYTE_SWAPEN_FIFO2;

		writeq(val64, &vpath_reg->kdfcctl_cfg0);
		wmb();
	}

	return VXGE_HW_OK;
}

/*
 * vxge_hw_vpath_strip_fcs_check - Check for FCS strip.
 */
enum vxge_hw_status
vxge_hw_vpath_strip_fcs_check(struct __vxge_hw_device *hldev, u64 vpath_mask)
{
	struct vxge_hw_vpmgmt_reg	__iomem *vpmgmt_reg;
	enum vxge_hw_status status = VXGE_HW_OK;
	int i = 0, j = 0;

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {
		if (!((vpath_mask) & vxge_mBIT(i)))
			continue;
		vpmgmt_reg = hldev->vpmgmt_reg[i];
		for (j = 0; j < VXGE_HW_MAC_MAX_MAC_PORT_ID; j++) {
			if (readq(&vpmgmt_reg->rxmac_cfg0_port_vpmgmt_clone[j])
			& VXGE_HW_RXMAC_CFG0_PORT_VPMGMT_CLONE_STRIP_FCS)
				return VXGE_HW_FAIL;
		}
	}
	return status;
}

/*
 * __vxge_hw_fifo_create - Create a FIFO
 * This function creates FIFO and initializes it.
 */
enum vxge_hw_status
__vxge_hw_fifo_create(struct __vxge_hw_virtualpath *vpath,
			struct __vxge_hw_fifo *fifo)
{
	enum vxge_hw_status status = VXGE_HW_OK;

	vxge_trace();

	fifo->vpathh = vpath;
	fifo->depth = VXGE_HW_FIFO_TXD_DEPTH;
	fifo->hw_offset = fifo->sw_offset = 0;
	fifo->nofl_db = vpath->nofl_db;
	fifo->vp_id = vpath->vp_id;
	fifo->vp_reg = vpath->vp_reg;
	fifo->tx_intr_num = (vpath->vp_id * VXGE_HW_MAX_INTR_PER_VP)
				+ VXGE_HW_VPATH_INTR_TX;

	fifo->txdl = malloc_dma(sizeof(struct vxge_hw_fifo_txd)
				* fifo->depth, fifo->depth);
	if (!fifo->txdl) {
		vxge_debug(VXGE_ERR, "%s:%d malloc_dma error\n",
				__func__, __LINE__);
		return VXGE_HW_ERR_OUT_OF_MEMORY;
	}
	memset(fifo->txdl, 0, sizeof(struct vxge_hw_fifo_txd) * fifo->depth);
	return status;
}

/*
 * __vxge_hw_fifo_delete - Removes the FIFO
 * This function freeup the memory pool and removes the FIFO
 */
enum vxge_hw_status __vxge_hw_fifo_delete(struct __vxge_hw_fifo *fifo)
{
	vxge_trace();

	if (fifo->txdl)
		free_dma(fifo->txdl,
			sizeof(struct vxge_hw_fifo_txd) * fifo->depth);

	fifo->txdl = NULL;
	fifo->hw_offset = fifo->sw_offset = 0;

	return VXGE_HW_OK;
}

/*
 * __vxge_hw_vpath_pci_read - Read the content of given address
 *                          in pci config space.
 * Read from the vpath pci config space.
 */
enum vxge_hw_status
__vxge_hw_vpath_pci_read(struct __vxge_hw_virtualpath *vpath,
			 u32 phy_func_0, u32 offset, u32 *val)
{
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_hw_vpath_reg __iomem *vp_reg = vpath->vp_reg;

	val64 =	VXGE_HW_PCI_CONFIG_ACCESS_CFG1_ADDRESS(offset);

	if (phy_func_0)
		val64 |= VXGE_HW_PCI_CONFIG_ACCESS_CFG1_SEL_FUNC0;

	writeq(val64, &vp_reg->pci_config_access_cfg1);
	wmb();
	writeq(VXGE_HW_PCI_CONFIG_ACCESS_CFG2_REQ,
			&vp_reg->pci_config_access_cfg2);
	wmb();

	status = __vxge_hw_device_register_poll(
			&vp_reg->pci_config_access_cfg2,
			VXGE_HW_INTR_MASK_ALL, VXGE_HW_DEF_DEVICE_POLL_MILLIS);

	if (status != VXGE_HW_OK)
		goto exit;

	val64 = readq(&vp_reg->pci_config_access_status);

	if (val64 & VXGE_HW_PCI_CONFIG_ACCESS_STATUS_ACCESS_ERR) {
		status = VXGE_HW_FAIL;
		*val = 0;
	} else
		*val = (u32)vxge_bVALn(val64, 32, 32);
exit:
	return status;
}

/*
 * __vxge_hw_vpath_func_id_get - Get the function id of the vpath.
 * Returns the function number of the vpath.
 */
u32
__vxge_hw_vpath_func_id_get(struct vxge_hw_vpmgmt_reg __iomem *vpmgmt_reg)
{
	u64 val64;

	val64 = readq(&vpmgmt_reg->vpath_to_func_map_cfg1);

	return
	 (u32)VXGE_HW_VPATH_TO_FUNC_MAP_CFG1_GET_VPATH_TO_FUNC_MAP_CFG1(val64);
}

/*
 * __vxge_hw_read_rts_ds - Program RTS steering critieria
 */
static inline void
__vxge_hw_read_rts_ds(struct vxge_hw_vpath_reg __iomem *vpath_reg,
				u64 dta_struct_sel)
{
	writeq(0, &vpath_reg->rts_access_steer_ctrl);
	wmb();
	writeq(dta_struct_sel, &vpath_reg->rts_access_steer_data0);
	writeq(0, &vpath_reg->rts_access_steer_data1);
	wmb();
	return;
}

/*
 * __vxge_hw_vpath_card_info_get - Get the serial numbers,
 * part number and product description.
 */
enum vxge_hw_status
__vxge_hw_vpath_card_info_get(
	struct vxge_hw_vpath_reg __iomem *vpath_reg,
	struct vxge_hw_device_hw_info *hw_info)
{
	u32 i, j;
	u64 val64;
	u64 data1 = 0ULL;
	u64 data2 = 0ULL;
	enum vxge_hw_status status = VXGE_HW_OK;
	u8 *serial_number = hw_info->serial_number;
	u8 *part_number = hw_info->part_number;
	u8 *product_desc = hw_info->product_desc;

	__vxge_hw_read_rts_ds(vpath_reg,
		VXGE_HW_RTS_ACCESS_STEER_DATA0_MEMO_ITEM_SERIAL_NUMBER);

	val64 = VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION(
			VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_READ_MEMO_ENTRY) |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL(
			VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO) |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_OFFSET(0);

	status = __vxge_hw_pio_mem_write64(val64,
				&vpath_reg->rts_access_steer_ctrl,
				VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE,
				VXGE_HW_DEF_DEVICE_POLL_MILLIS);

	if (status != VXGE_HW_OK)
		return status;

	val64 = readq(&vpath_reg->rts_access_steer_ctrl);

	if (val64 & VXGE_HW_RTS_ACCESS_STEER_CTRL_RMACJ_STATUS) {
		data1 = readq(&vpath_reg->rts_access_steer_data0);
		((u64 *)serial_number)[0] = be64_to_cpu(data1);

		data2 = readq(&vpath_reg->rts_access_steer_data1);
		((u64 *)serial_number)[1] = be64_to_cpu(data2);
		status = VXGE_HW_OK;
	} else
		*serial_number = 0;

	__vxge_hw_read_rts_ds(vpath_reg,
			VXGE_HW_RTS_ACCESS_STEER_DATA0_MEMO_ITEM_PART_NUMBER);

	val64 = VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION(
			VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_READ_MEMO_ENTRY) |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL(
			VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO) |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_OFFSET(0);

	status = __vxge_hw_pio_mem_write64(val64,
				&vpath_reg->rts_access_steer_ctrl,
				VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE,
				VXGE_HW_DEF_DEVICE_POLL_MILLIS);

	if (status != VXGE_HW_OK)
		return status;

	val64 = readq(&vpath_reg->rts_access_steer_ctrl);

	if (val64 & VXGE_HW_RTS_ACCESS_STEER_CTRL_RMACJ_STATUS) {

		data1 = readq(&vpath_reg->rts_access_steer_data0);
		((u64 *)part_number)[0] = be64_to_cpu(data1);

		data2 = readq(&vpath_reg->rts_access_steer_data1);
		((u64 *)part_number)[1] = be64_to_cpu(data2);

		status = VXGE_HW_OK;

	} else
		*part_number = 0;

	j = 0;

	for (i = VXGE_HW_RTS_ACCESS_STEER_DATA0_MEMO_ITEM_DESC_0;
	     i <= VXGE_HW_RTS_ACCESS_STEER_DATA0_MEMO_ITEM_DESC_3; i++) {

		__vxge_hw_read_rts_ds(vpath_reg, i);

		val64 = VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION(
			VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_READ_MEMO_ENTRY) |
			VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL(
			VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO) |
			VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE |
			VXGE_HW_RTS_ACCESS_STEER_CTRL_OFFSET(0);

		status = __vxge_hw_pio_mem_write64(val64,
				&vpath_reg->rts_access_steer_ctrl,
				VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE,
				VXGE_HW_DEF_DEVICE_POLL_MILLIS);

		if (status != VXGE_HW_OK)
			return status;

		val64 = readq(&vpath_reg->rts_access_steer_ctrl);

		if (val64 & VXGE_HW_RTS_ACCESS_STEER_CTRL_RMACJ_STATUS) {

			data1 = readq(&vpath_reg->rts_access_steer_data0);
			((u64 *)product_desc)[j++] = be64_to_cpu(data1);

			data2 = readq(&vpath_reg->rts_access_steer_data1);
			((u64 *)product_desc)[j++] = be64_to_cpu(data2);

			status = VXGE_HW_OK;
		} else
			*product_desc = 0;
	}

	return status;
}

/*
 * __vxge_hw_vpath_fw_ver_get - Get the fw version
 * Returns FW Version
 */
enum vxge_hw_status
__vxge_hw_vpath_fw_ver_get(
	struct vxge_hw_vpath_reg __iomem *vpath_reg,
	struct vxge_hw_device_hw_info *hw_info)
{
	u64 val64;
	u64 data1 = 0ULL;
	u64 data2 = 0ULL;
	struct vxge_hw_device_version *fw_version = &hw_info->fw_version;
	struct vxge_hw_device_date *fw_date = &hw_info->fw_date;
	struct vxge_hw_device_version *flash_version = &hw_info->flash_version;
	struct vxge_hw_device_date *flash_date = &hw_info->flash_date;
	enum vxge_hw_status status = VXGE_HW_OK;

	val64 = VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION(
		VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_READ_ENTRY) |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL(
		VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_FW_MEMO) |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE |
		VXGE_HW_RTS_ACCESS_STEER_CTRL_OFFSET(0);

	status = __vxge_hw_pio_mem_write64(val64,
				&vpath_reg->rts_access_steer_ctrl,
				VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE,
				VXGE_HW_DEF_DEVICE_POLL_MILLIS);

	if (status != VXGE_HW_OK)
		goto exit;

	val64 = readq(&vpath_reg->rts_access_steer_ctrl);

	if (val64 & VXGE_HW_RTS_ACCESS_STEER_CTRL_RMACJ_STATUS) {

		data1 = readq(&vpath_reg->rts_access_steer_data0);
		data2 = readq(&vpath_reg->rts_access_steer_data1);

		fw_date->day =
			(u32)VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_FW_VER_DAY(
						data1);
		fw_date->month =
			(u32)VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_FW_VER_MONTH(
						data1);
		fw_date->year =
			(u32)VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_FW_VER_YEAR(
						data1);

		snprintf(fw_date->date, VXGE_HW_FW_STRLEN, "%d/%d/%d",
			fw_date->month, fw_date->day, fw_date->year);

		fw_version->major =
		    (u32)VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_FW_VER_MAJOR(data1);
		fw_version->minor =
		    (u32)VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_FW_VER_MINOR(data1);
		fw_version->build =
		    (u32)VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_FW_VER_BUILD(data1);

		snprintf(fw_version->version, VXGE_HW_FW_STRLEN, "%d.%d.%d",
		    fw_version->major, fw_version->minor, fw_version->build);

		flash_date->day =
		  (u32)VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_FLASH_VER_DAY(data2);
		flash_date->month =
		 (u32)VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_FLASH_VER_MONTH(data2);
		flash_date->year =
		 (u32)VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_FLASH_VER_YEAR(data2);

		snprintf(flash_date->date, VXGE_HW_FW_STRLEN, "%d/%d/%d",
			flash_date->month, flash_date->day, flash_date->year);

		flash_version->major =
		 (u32)VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_FLASH_VER_MAJOR(data2);
		flash_version->minor =
		 (u32)VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_FLASH_VER_MINOR(data2);
		flash_version->build =
		 (u32)VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_FLASH_VER_BUILD(data2);

		snprintf(flash_version->version, VXGE_HW_FW_STRLEN, "%d.%d.%d",
			flash_version->major, flash_version->minor,
			flash_version->build);

		status = VXGE_HW_OK;

	} else
		status = VXGE_HW_FAIL;
exit:
	return status;
}

/*
 * __vxge_hw_vpath_addr_get - Get the hw address entry for this vpath
 *               from MAC address table.
 */
enum vxge_hw_status
__vxge_hw_vpath_addr_get(
	struct vxge_hw_vpath_reg *vpath_reg,
	u8 (macaddr)[ETH_ALEN], u8 (macaddr_mask)[ETH_ALEN])
{
	u32 i;
	u64 val64;
	u64 data1 = 0ULL;
	u64 data2 = 0ULL;
	u64 action = VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_LIST_FIRST_ENTRY;
	enum vxge_hw_status status = VXGE_HW_OK;

	while (1) {
		val64 = VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION(action) |
			VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL(
			VXGE_HW_RTS_ACCESS_STEER_CTRL_DATA_STRUCT_SEL_DA) |
			VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE |
			VXGE_HW_RTS_ACCESS_STEER_CTRL_OFFSET(0);

		status = __vxge_hw_pio_mem_write64(val64,
					&vpath_reg->rts_access_steer_ctrl,
					VXGE_HW_RTS_ACCESS_STEER_CTRL_STROBE,
					VXGE_HW_DEF_DEVICE_POLL_MILLIS);

		if (status != VXGE_HW_OK)
			break;

		val64 = readq(&vpath_reg->rts_access_steer_ctrl);

		if (val64 & VXGE_HW_RTS_ACCESS_STEER_CTRL_RMACJ_STATUS) {

			data1 = readq(&vpath_reg->rts_access_steer_data0);
			data2 = readq(&vpath_reg->rts_access_steer_data1);

			data1 =
			 VXGE_HW_RTS_ACCESS_STEER_DATA0_GET_DA_MAC_ADDR(data1);
			data2 =
			 VXGE_HW_RTS_ACCESS_STEER_DATA1_GET_DA_MAC_ADDR_MASK(
								data2);

			for (i = ETH_ALEN; i > 0; i--) {
				macaddr[i-1] = (u8)(data1 & 0xFF);
				data1 >>= 8;

				macaddr_mask[i-1] = (u8)(data2 & 0xFF);
				data2 >>= 8;
			}
			if (is_valid_ether_addr(macaddr)) {
				status = VXGE_HW_OK;
				break;
			}
			action =
			  VXGE_HW_RTS_ACCESS_STEER_CTRL_ACTION_LIST_NEXT_ENTRY;
		} else
			status = VXGE_HW_FAIL;
	}

	return status;
}

/*
 * __vxge_hw_vpath_mgmt_read
 * This routine reads the vpath_mgmt registers
 */
static enum vxge_hw_status
__vxge_hw_vpath_mgmt_read(
	struct __vxge_hw_virtualpath *vpath)
{
	u32 i, mtu = 0, max_pyld = 0;
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;

	for (i = 0; i < VXGE_HW_MAC_MAX_MAC_PORT_ID; i++) {

		val64 = readq(&vpath->vpmgmt_reg->
				rxmac_cfg0_port_vpmgmt_clone[i]);
		max_pyld =
			(u32)
			VXGE_HW_RXMAC_CFG0_PORT_VPMGMT_CLONE_GET_MAX_PYLD_LEN
			(val64);
		if (mtu < max_pyld)
			mtu = max_pyld;
	}

	vpath->max_mtu = mtu + VXGE_HW_MAC_HEADER_MAX_SIZE;

	val64 = readq(&vpath->vpmgmt_reg->xgmac_gen_status_vpmgmt_clone);

	if (val64 & VXGE_HW_XGMAC_GEN_STATUS_VPMGMT_CLONE_XMACJ_NTWK_OK)
		VXGE_HW_DEVICE_LINK_STATE_SET(vpath->hldev, VXGE_HW_LINK_UP);
	else
		VXGE_HW_DEVICE_LINK_STATE_SET(vpath->hldev, VXGE_HW_LINK_DOWN);

	return status;
}

/*
 * __vxge_hw_vpath_reset_check - Check if resetting the vpath completed
 * This routine checks the vpath_rst_in_prog register to see if
 * adapter completed the reset process for the vpath
 */
enum vxge_hw_status
__vxge_hw_vpath_reset_check(struct __vxge_hw_virtualpath *vpath)
{
	enum vxge_hw_status status;

	vxge_trace();

	status = __vxge_hw_device_register_poll(
			&vpath->hldev->common_reg->vpath_rst_in_prog,
			VXGE_HW_VPATH_RST_IN_PROG_VPATH_RST_IN_PROG(
				1 << (16 - vpath->vp_id)),
			VXGE_HW_DEF_DEVICE_POLL_MILLIS);

	return status;
}

/*
 * __vxge_hw_vpath_reset
 * This routine resets the vpath on the device
 */
enum vxge_hw_status
__vxge_hw_vpath_reset(struct __vxge_hw_device *hldev, u32 vp_id)
{
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;

	vxge_trace();

	val64 = VXGE_HW_CMN_RSTHDLR_CFG0_SW_RESET_VPATH(1 << (16 - vp_id));

	__vxge_hw_pio_mem_write32_upper((u32)vxge_bVALn(val64, 0, 32),
				&hldev->common_reg->cmn_rsthdlr_cfg0);

	return status;
}

/*
 * __vxge_hw_vpath_prc_configure
 * This routine configures the prc registers of virtual path using the config
 * passed
 */
void
__vxge_hw_vpath_prc_configure(struct __vxge_hw_device *hldev)
{
	u64 val64;
	struct __vxge_hw_virtualpath *vpath;
	struct vxge_hw_vpath_reg __iomem *vp_reg;

	vxge_trace();

	vpath = &hldev->virtual_path;
	vp_reg = vpath->vp_reg;

	val64 = readq(&vp_reg->prc_cfg1);
	val64 |= VXGE_HW_PRC_CFG1_RTI_TINT_DISABLE;
	writeq(val64, &vp_reg->prc_cfg1);

	val64 = readq(&vpath->vp_reg->prc_cfg6);
	val64 &= ~VXGE_HW_PRC_CFG6_RXD_CRXDT(0x1ff);
	val64 &= ~VXGE_HW_PRC_CFG6_RXD_SPAT(0x1ff);
	val64 |= VXGE_HW_PRC_CFG6_DOORBELL_MODE_EN;
	val64 |= VXGE_HW_PRC_CFG6_RXD_CRXDT(0x3);
	val64 |= VXGE_HW_PRC_CFG6_RXD_SPAT(0xf);
	writeq(val64, &vpath->vp_reg->prc_cfg6);

	writeq(VXGE_HW_PRC_CFG5_RXD0_ADD(
			(u64)virt_to_bus(vpath->ringh.rxdl) >> 3),
			&vp_reg->prc_cfg5);

	val64 = readq(&vp_reg->prc_cfg4);
	val64 |= VXGE_HW_PRC_CFG4_IN_SVC;
	val64 &= ~VXGE_HW_PRC_CFG4_RING_MODE(0x3);
	val64 |= VXGE_HW_PRC_CFG4_RING_MODE(
			VXGE_HW_PRC_CFG4_RING_MODE_ONE_BUFFER);
	val64 |= VXGE_HW_PRC_CFG4_RTH_DISABLE;

	writeq(val64, &vp_reg->prc_cfg4);
	return;
}

/*
 * __vxge_hw_vpath_kdfc_configure
 * This routine configures the kdfc registers of virtual path using the
 * config passed
 */
enum vxge_hw_status
__vxge_hw_vpath_kdfc_configure(struct __vxge_hw_device *hldev, u32 vp_id)
{
	u64 val64;
	u64 vpath_stride;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_virtualpath *vpath;
	struct vxge_hw_vpath_reg __iomem *vp_reg;

	vxge_trace();

	vpath = &hldev->virtual_path;
	vp_reg = vpath->vp_reg;
	status = __vxge_hw_kdfc_swapper_set(hldev->legacy_reg, vp_reg);

	if (status != VXGE_HW_OK)
		goto exit;

	val64 = readq(&vp_reg->kdfc_drbl_triplet_total);

	vpath->max_kdfc_db =
		(u32)VXGE_HW_KDFC_DRBL_TRIPLET_TOTAL_GET_KDFC_MAX_SIZE(
			val64+1)/2;

	vpath->max_nofl_db = vpath->max_kdfc_db;

	val64 = VXGE_HW_KDFC_FIFO_TRPL_PARTITION_LENGTH_0(
				(vpath->max_nofl_db*2)-1);

	writeq(val64, &vp_reg->kdfc_fifo_trpl_partition);

	writeq(VXGE_HW_KDFC_FIFO_TRPL_CTRL_TRIPLET_ENABLE,
		&vp_reg->kdfc_fifo_trpl_ctrl);

	val64 = readq(&vp_reg->kdfc_trpl_fifo_0_ctrl);

	val64 &= ~(VXGE_HW_KDFC_TRPL_FIFO_0_CTRL_MODE(0x3) |
		   VXGE_HW_KDFC_TRPL_FIFO_0_CTRL_SELECT(0xFF));

	val64 |= VXGE_HW_KDFC_TRPL_FIFO_0_CTRL_MODE(
		 VXGE_HW_KDFC_TRPL_FIFO_0_CTRL_MODE_NON_OFFLOAD_ONLY) |
#if (__BYTE_ORDER != __BIG_ENDIAN)
		 VXGE_HW_KDFC_TRPL_FIFO_0_CTRL_SWAP_EN |
#endif
		 VXGE_HW_KDFC_TRPL_FIFO_0_CTRL_SELECT(0);

	writeq(val64, &vp_reg->kdfc_trpl_fifo_0_ctrl);
	writeq((u64)0, &vp_reg->kdfc_trpl_fifo_0_wb_address);
	wmb();
	vpath_stride = readq(&hldev->toc_reg->toc_kdfc_vpath_stride);

	vpath->nofl_db =
		(struct __vxge_hw_non_offload_db_wrapper __iomem *)
		(hldev->kdfc + (vp_id *
		VXGE_HW_TOC_KDFC_VPATH_STRIDE_GET_TOC_KDFC_VPATH_STRIDE(
					vpath_stride)));
exit:
	return status;
}

/*
 * __vxge_hw_vpath_mac_configure
 * This routine configures the mac of virtual path using the config passed
 */
enum vxge_hw_status
__vxge_hw_vpath_mac_configure(struct __vxge_hw_device *hldev)
{
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_virtualpath *vpath;
	struct vxge_hw_vpath_reg __iomem *vp_reg;

	vxge_trace();

	vpath = &hldev->virtual_path;
	vp_reg = vpath->vp_reg;

	writeq(VXGE_HW_XMAC_VSPORT_CHOICE_VSPORT_NUMBER(
			vpath->vsport_number), &vp_reg->xmac_vsport_choice);

	val64 = readq(&vp_reg->rxmac_vcfg1);

	val64 &= ~(VXGE_HW_RXMAC_VCFG1_RTS_RTH_MULTI_IT_BD_MODE(0x3) |
		VXGE_HW_RXMAC_VCFG1_RTS_RTH_MULTI_IT_EN_MODE);

	writeq(val64, &vp_reg->rxmac_vcfg1);
	return status;
}

/*
 * __vxge_hw_vpath_tim_configure
 * This routine configures the tim registers of virtual path using the config
 * passed
 */
enum vxge_hw_status
__vxge_hw_vpath_tim_configure(struct __vxge_hw_device *hldev, u32 vp_id)
{
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_virtualpath *vpath;
	struct vxge_hw_vpath_reg __iomem *vp_reg;

	vxge_trace();

	vpath = &hldev->virtual_path;
	vp_reg = vpath->vp_reg;

	writeq((u64)0, &vp_reg->tim_dest_addr);
	writeq((u64)0, &vp_reg->tim_vpath_map);
	writeq((u64)0, &vp_reg->tim_bitmap);
	writeq((u64)0, &vp_reg->tim_remap);

	writeq(VXGE_HW_TIM_RING_ASSN_INT_NUM(
		(vp_id * VXGE_HW_MAX_INTR_PER_VP) +
		VXGE_HW_VPATH_INTR_RX), &vp_reg->tim_ring_assn);

	val64 = readq(&vp_reg->tim_pci_cfg);
	val64 |= VXGE_HW_TIM_PCI_CFG_ADD_PAD;
	writeq(val64, &vp_reg->tim_pci_cfg);

	/* TX configuration */
	val64 = VXGE_HW_TIM_CFG1_INT_NUM_BTIMER_VAL(
			(VXGE_TTI_BTIMER_VAL * 1000) / 272);
	val64 |= (VXGE_HW_TIM_CFG1_INT_NUM_TIMER_AC |
			VXGE_HW_TIM_CFG1_INT_NUM_TIMER_CI |
			VXGE_HW_TIM_CFG1_INT_NUM_TXFRM_CNT_EN);
	val64 |= VXGE_HW_TIM_CFG1_INT_NUM_URNG_A(TTI_TX_URANGE_A) |
			VXGE_HW_TIM_CFG1_INT_NUM_URNG_B(TTI_TX_URANGE_B) |
			VXGE_HW_TIM_CFG1_INT_NUM_URNG_C(TTI_TX_URANGE_C);
	writeq(val64, &vp_reg->tim_cfg1_int_num[VXGE_HW_VPATH_INTR_TX]);

	val64 = VXGE_HW_TIM_CFG2_INT_NUM_UEC_A(TTI_TX_UFC_A) |
			VXGE_HW_TIM_CFG2_INT_NUM_UEC_B(TTI_TX_UFC_B) |
			VXGE_HW_TIM_CFG2_INT_NUM_UEC_C(TTI_TX_UFC_C) |
			VXGE_HW_TIM_CFG2_INT_NUM_UEC_D(TTI_TX_UFC_D);
	writeq(val64, &vp_reg->tim_cfg2_int_num[VXGE_HW_VPATH_INTR_TX]);

	val64 = VXGE_HW_TIM_CFG3_INT_NUM_UTIL_SEL(
			VXGE_HW_TIM_UTIL_SEL_LEGACY_TX_NET_UTIL);
	val64 |= VXGE_HW_TIM_CFG3_INT_NUM_LTIMER_VAL(
			(VXGE_TTI_LTIMER_VAL * 1000) / 272);
	writeq(val64, &vp_reg->tim_cfg3_int_num[VXGE_HW_VPATH_INTR_TX]);

	/* RX configuration */
	val64 = VXGE_HW_TIM_CFG1_INT_NUM_BTIMER_VAL(
			(VXGE_RTI_BTIMER_VAL * 1000) / 272);
	val64 |= VXGE_HW_TIM_CFG1_INT_NUM_TIMER_AC;
	val64 |= VXGE_HW_TIM_CFG1_INT_NUM_URNG_A(RTI_RX_URANGE_A) |
			VXGE_HW_TIM_CFG1_INT_NUM_URNG_B(RTI_RX_URANGE_B) |
			VXGE_HW_TIM_CFG1_INT_NUM_URNG_C(RTI_RX_URANGE_C);
	writeq(val64, &vp_reg->tim_cfg1_int_num[VXGE_HW_VPATH_INTR_RX]);

	val64 = VXGE_HW_TIM_CFG2_INT_NUM_UEC_A(RTI_RX_UFC_A) |
			VXGE_HW_TIM_CFG2_INT_NUM_UEC_B(RTI_RX_UFC_B) |
			VXGE_HW_TIM_CFG2_INT_NUM_UEC_C(RTI_RX_UFC_C) |
			VXGE_HW_TIM_CFG2_INT_NUM_UEC_D(RTI_RX_UFC_D);
	writeq(val64, &vp_reg->tim_cfg2_int_num[VXGE_HW_VPATH_INTR_RX]);

	val64 = VXGE_HW_TIM_CFG3_INT_NUM_UTIL_SEL(
			VXGE_HW_TIM_UTIL_SEL_LEGACY_RX_NET_UTIL);
	val64 |= VXGE_HW_TIM_CFG3_INT_NUM_LTIMER_VAL(
			(VXGE_RTI_LTIMER_VAL * 1000) / 272);
	writeq(val64, &vp_reg->tim_cfg3_int_num[VXGE_HW_VPATH_INTR_RX]);

	val64 = 0;
	writeq(val64, &vp_reg->tim_cfg1_int_num[VXGE_HW_VPATH_INTR_EINTA]);
	writeq(val64, &vp_reg->tim_cfg2_int_num[VXGE_HW_VPATH_INTR_EINTA]);
	writeq(val64, &vp_reg->tim_cfg3_int_num[VXGE_HW_VPATH_INTR_EINTA]);
	writeq(val64, &vp_reg->tim_cfg1_int_num[VXGE_HW_VPATH_INTR_BMAP]);
	writeq(val64, &vp_reg->tim_cfg2_int_num[VXGE_HW_VPATH_INTR_BMAP]);
	writeq(val64, &vp_reg->tim_cfg3_int_num[VXGE_HW_VPATH_INTR_BMAP]);

	return status;
}

/*
 * __vxge_hw_vpath_initialize
 * This routine is the final phase of init which initializes the
 * registers of the vpath using the configuration passed.
 */
enum vxge_hw_status
__vxge_hw_vpath_initialize(struct __vxge_hw_device *hldev, u32 vp_id)
{
	u64 val64;
	u32 val32;
	int i;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_virtualpath *vpath;
	struct vxge_hw_vpath_reg *vp_reg;

	vxge_trace();

	vpath = &hldev->virtual_path;

	if (!(hldev->vpath_assignments & vxge_mBIT(vp_id))) {
		status = VXGE_HW_ERR_VPATH_NOT_AVAILABLE;
		goto exit;
	}
	vp_reg = vpath->vp_reg;
	status = __vxge_hw_legacy_swapper_set(hldev->legacy_reg);
	if (status != VXGE_HW_OK)
		goto exit;

	status = __vxge_hw_vpath_swapper_set(vpath->vp_reg);

	if (status != VXGE_HW_OK)
		goto exit;
	val64 = readq(&vpath->vpmgmt_reg->xmac_vsport_choices_vp);

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {
		if (val64 & vxge_mBIT(i))
			vpath->vsport_number = i;
	}

	status = __vxge_hw_vpath_mac_configure(hldev);

	if (status != VXGE_HW_OK)
		goto exit;

	status = __vxge_hw_vpath_kdfc_configure(hldev, vp_id);

	if (status != VXGE_HW_OK)
		goto exit;

	status = __vxge_hw_vpath_tim_configure(hldev, vp_id);

	if (status != VXGE_HW_OK)
		goto exit;

	val64 = readq(&vp_reg->rtdma_rd_optimization_ctrl);

	/* Get MRRS value from device control */
	status = __vxge_hw_vpath_pci_read(vpath, 1, 0x78, &val32);

	if (status == VXGE_HW_OK) {
		val32 = (val32 & VXGE_HW_PCI_EXP_DEVCTL_READRQ) >> 12;
		val64 &=
		    ~(VXGE_HW_RTDMA_RD_OPTIMIZATION_CTRL_FB_FILL_THRESH(7));
		val64 |=
		    VXGE_HW_RTDMA_RD_OPTIMIZATION_CTRL_FB_FILL_THRESH(val32);

		val64 |= VXGE_HW_RTDMA_RD_OPTIMIZATION_CTRL_FB_WAIT_FOR_SPACE;
	}

	val64 &= ~(VXGE_HW_RTDMA_RD_OPTIMIZATION_CTRL_FB_ADDR_BDRY(7));
	val64 |=
	    VXGE_HW_RTDMA_RD_OPTIMIZATION_CTRL_FB_ADDR_BDRY(
		    VXGE_HW_MAX_PAYLOAD_SIZE_512);

	val64 |= VXGE_HW_RTDMA_RD_OPTIMIZATION_CTRL_FB_ADDR_BDRY_EN;
	writeq(val64, &vp_reg->rtdma_rd_optimization_ctrl);

exit:
	return status;
}

/*
 * __vxge_hw_vp_initialize - Initialize Virtual Path structure
 * This routine is the initial phase of init which resets the vpath and
 * initializes the software support structures.
 */
enum vxge_hw_status
__vxge_hw_vp_initialize(struct __vxge_hw_device *hldev, u32 vp_id,
			struct __vxge_hw_virtualpath *vpath)
{
	enum vxge_hw_status status = VXGE_HW_OK;

	vxge_trace();

	if (!(hldev->vpath_assignments & vxge_mBIT(vp_id))) {
		status = VXGE_HW_ERR_VPATH_NOT_AVAILABLE;
		goto exit;
	}

	vpath->vp_id = vp_id;
	vpath->vp_open = VXGE_HW_VP_OPEN;
	vpath->hldev = hldev;
	vpath->vp_reg = hldev->vpath_reg[vp_id];
	vpath->vpmgmt_reg = hldev->vpmgmt_reg[vp_id];

	__vxge_hw_vpath_reset(hldev, vp_id);

	status = __vxge_hw_vpath_reset_check(vpath);
	if (status != VXGE_HW_OK) {
		memset(vpath, 0, sizeof(struct __vxge_hw_virtualpath));
		goto exit;
	}

	VXGE_HW_DEVICE_TIM_INT_MASK_SET(hldev->tim_int_mask0,
		hldev->tim_int_mask1, vp_id);

	status = __vxge_hw_vpath_initialize(hldev, vp_id);

	if (status != VXGE_HW_OK) {
		__vxge_hw_vp_terminate(hldev, vpath);
		goto exit;
	}

	status = __vxge_hw_vpath_mgmt_read(vpath);
exit:
	return status;
}

/*
 * __vxge_hw_vp_terminate - Terminate Virtual Path structure
 * This routine closes all channels it opened and freeup memory
 */
void
__vxge_hw_vp_terminate(struct __vxge_hw_device *hldev,
			struct __vxge_hw_virtualpath *vpath)
{
	vxge_trace();

	if (vpath->vp_open == VXGE_HW_VP_NOT_OPEN)
		return;

	VXGE_HW_DEVICE_TIM_INT_MASK_RESET(hldev->tim_int_mask0,
		hldev->tim_int_mask1, vpath->vp_id);

	memset(vpath, 0, sizeof(struct __vxge_hw_virtualpath));
}

/*
 * vxge_hw_vpath_mtu_set - Set MTU.
 * Set new MTU value. Example, to use jumbo frames:
 * vxge_hw_vpath_mtu_set(my_device, 9600);
 */
enum vxge_hw_status
vxge_hw_vpath_mtu_set(struct __vxge_hw_virtualpath *vpath, u32 new_mtu)
{
	u64 val64;
	enum vxge_hw_status status = VXGE_HW_OK;

	vxge_trace();

	new_mtu += VXGE_HW_MAC_HEADER_MAX_SIZE;

	if ((new_mtu < VXGE_HW_MIN_MTU) || (new_mtu > vpath->max_mtu))
		status = VXGE_HW_ERR_INVALID_MTU_SIZE;

	val64 = readq(&vpath->vp_reg->rxmac_vcfg0);

	val64 &= ~VXGE_HW_RXMAC_VCFG0_RTS_MAX_FRM_LEN(0x3fff);
	val64 |= VXGE_HW_RXMAC_VCFG0_RTS_MAX_FRM_LEN(new_mtu);

	writeq(val64, &vpath->vp_reg->rxmac_vcfg0);

	return status;
}

/*
 * vxge_hw_vpath_open - Open a virtual path on a given adapter
 * This function is used to open access to virtual path of an
 * adapter for offload, GRO operations. This function returns
 * synchronously.
 */
enum vxge_hw_status
vxge_hw_vpath_open(struct __vxge_hw_device *hldev, struct vxge_vpath *vpath)
{
	struct __vxge_hw_virtualpath *vpathh;
	enum vxge_hw_status status;

	vxge_trace();

	vpathh = &hldev->virtual_path;

	if (vpath->vp_open == VXGE_HW_VP_OPEN) {
		status = VXGE_HW_ERR_INVALID_STATE;
		goto vpath_open_exit1;
	}

	status = __vxge_hw_vp_initialize(hldev, hldev->first_vp_id, vpathh);
	if (status != VXGE_HW_OK)
		goto vpath_open_exit1;

	status = __vxge_hw_fifo_create(vpathh, &vpathh->fifoh);
	if (status != VXGE_HW_OK)
		goto vpath_open_exit2;

	status = __vxge_hw_ring_create(vpathh, &vpathh->ringh);
	if (status != VXGE_HW_OK)
		goto vpath_open_exit3;

	__vxge_hw_vpath_prc_configure(hldev);

	return VXGE_HW_OK;

vpath_open_exit3:
	__vxge_hw_fifo_delete(&vpathh->fifoh);
vpath_open_exit2:
	__vxge_hw_vp_terminate(hldev, vpathh);
vpath_open_exit1:
	return status;
}

/*
 * vxge_hw_vpath_rx_doorbell_init -  Post the count of the refreshed region
 * of RxD list
 * @vp: vpath handle
 *
 * This function decides on the Rxd replenish count depending on the
 * descriptor memory that has been allocated to this VPath.
 */
void
vxge_hw_vpath_rx_doorbell_init(struct __vxge_hw_virtualpath *vpath)
{
	u64 new_count, val64;

	vxge_trace();

	if (vpath->hldev->titan1) {
		new_count = readq(&vpath->vp_reg->rxdmem_size);
		new_count &= 0x1fff;
	} else
		new_count = VXGE_HW_RING_RXD_QWORDS_MODE_1 * 4;

	val64 = (VXGE_HW_RXDMEM_SIZE_PRC_RXDMEM_SIZE(new_count));

	writeq(VXGE_HW_PRC_RXD_DOORBELL_NEW_QW_CNT(val64),
		&vpath->vp_reg->prc_rxd_doorbell);
}

/*
 * vxge_hw_vpath_close - Close the handle got from previous vpath (vpath) open
 * This function is used to close access to virtual path opened
 * earlier.
 */
enum vxge_hw_status vxge_hw_vpath_close(struct __vxge_hw_virtualpath *vpath)
{
	struct __vxge_hw_device *devh = NULL;
	u32 vp_id = vpath->vp_id;
	enum vxge_hw_status status = VXGE_HW_OK;

	vxge_trace();

	devh = vpath->hldev;

	if (vpath->vp_open == VXGE_HW_VP_NOT_OPEN) {
		status = VXGE_HW_ERR_VPATH_NOT_OPEN;
		goto vpath_close_exit;
	}

	devh->vpaths_deployed &= ~vxge_mBIT(vp_id);

	__vxge_hw_ring_delete(&vpath->ringh);

	__vxge_hw_fifo_delete(&vpath->fifoh);

	__vxge_hw_vp_terminate(devh, vpath);

	vpath->vp_open = VXGE_HW_VP_NOT_OPEN;

vpath_close_exit:
	return status;
}

/*
 * vxge_hw_vpath_reset - Resets vpath
 * This function is used to request a reset of vpath
 */
enum vxge_hw_status vxge_hw_vpath_reset(struct __vxge_hw_virtualpath *vpath)
{
	enum vxge_hw_status status;
	u32 vp_id;

	vxge_trace();

	vp_id = vpath->vp_id;

	if (vpath->vp_open == VXGE_HW_VP_NOT_OPEN) {
		status = VXGE_HW_ERR_VPATH_NOT_OPEN;
		goto exit;
	}

	status = __vxge_hw_vpath_reset(vpath->hldev, vp_id);
exit:
	return status;
}

/*
 * vxge_hw_vpath_recover_from_reset - Poll for reset complete and re-initialize.
 * This function poll's for the vpath reset completion and re initializes
 * the vpath.
 */
enum vxge_hw_status
vxge_hw_vpath_recover_from_reset(struct __vxge_hw_virtualpath *vpath)
{
	enum vxge_hw_status status;
	struct __vxge_hw_device *hldev;
	u32 vp_id;

	vxge_trace();

	vp_id = vpath->vp_id;
	hldev = vpath->hldev;

	if (vpath->vp_open == VXGE_HW_VP_NOT_OPEN) {
		status = VXGE_HW_ERR_VPATH_NOT_OPEN;
		goto exit;
	}

	status = __vxge_hw_vpath_reset_check(vpath);
	if (status != VXGE_HW_OK)
		goto exit;

	status = __vxge_hw_vpath_initialize(hldev, vp_id);
	if (status != VXGE_HW_OK)
		goto exit;

	__vxge_hw_vpath_prc_configure(hldev);

exit:
	return status;
}

/*
 * vxge_hw_vpath_enable - Enable vpath.
 * This routine clears the vpath reset thereby enabling a vpath
 * to start forwarding frames and generating interrupts.
 */
void
vxge_hw_vpath_enable(struct __vxge_hw_virtualpath *vpath)
{
	struct __vxge_hw_device *hldev;
	u64 val64;

	vxge_trace();

	hldev = vpath->hldev;

	val64 = VXGE_HW_CMN_RSTHDLR_CFG1_CLR_VPATH_RESET(
		1 << (16 - vpath->vp_id));

	__vxge_hw_pio_mem_write32_upper((u32)vxge_bVALn(val64, 0, 32),
		&hldev->common_reg->cmn_rsthdlr_cfg1);
}
