/*
 * vxge-main.c: iPXE driver for Neterion Inc's X3100 Series 10GbE
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ipxe/io.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/pci.h>
#include <ipxe/malloc.h>
#include <ipxe/if_ether.h>
#include <ipxe/ethernet.h>
#include <ipxe/iobuf.h>
#include <ipxe/netdevice.h>
#include <ipxe/timer.h>
#include <nic.h>

#include "vxge_main.h"
#include "vxge_reg.h"

/* function modes strings */
static char *vxge_func_mode_names[] = {
	"Single Function - 1 func, 17 vpath",
	"Multi Function 8 - 8 func, 2 vpath per func",
	"SRIOV 17 - 17 VF, 1 vpath per VF",
	"WLPEX/SharedIO 17 - 17 VH, 1 vpath/func/hierarchy",
	"WLPEX/SharedIO 8 - 8 VH, 2 vpath/func/hierarchy",
	"Multi Function 17 - 17 func, 1 vpath per func",
	"SRIOV 8 - 1 PF, 7 VF, 2 vpath per VF",
	"SRIOV 4 - 1 PF, 3 VF, 4 vpath per VF",
	"Multi Function 2 - 2 func, 8 vpath per func",
	"Multi Function 4 - 4 func, 4 vpath per func",
	"WLPEX/SharedIO 4 - 17 func, 1 vpath per func (PCIe ARI)",
	"Multi Function 8 - For ESX DirectIO - 8 func, 2 vpath per func",
};

static inline int is_vxge_card_up(struct vxgedev *vdev)
{
	return test_bit(__VXGE_STATE_CARD_UP, vdev->state);
}

/*
 * vxge_xmit_compl
 *
 * If an interrupt was raised to indicate DMA complete of the Tx packet,
 * this function is called. It identifies the last TxD whose buffer was
 * freed and frees all skbs whose data have already DMA'ed into the NICs
 * internal memory.
 */
enum vxge_hw_status
vxge_xmit_compl(struct __vxge_hw_fifo *fifo_hw,
		struct vxge_hw_fifo_txd *txdp, enum vxge_hw_fifo_tcode tcode)
{
	struct net_device *netdev;
	struct io_buffer *tx_iob = NULL;

	vxge_trace();

	netdev = fifo_hw->vpathh->hldev->ndev;

	tx_iob = (struct io_buffer *)(intptr_t)txdp->host_control;

	if (tcode == VXGE_HW_FIFO_T_CODE_OK) {
		netdev_tx_complete(netdev, tx_iob);
	} else {
		netdev_tx_complete_err(netdev, tx_iob, -EINVAL);
		vxge_debug(VXGE_ERR, "%s: transmit failed, tcode %d\n",
				netdev->name, tcode);
	}

	memset(txdp, 0, sizeof(struct vxge_hw_fifo_txd));

	return VXGE_HW_OK;
}

/* reset vpaths */
enum vxge_hw_status vxge_reset_all_vpaths(struct vxgedev *vdev)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct __vxge_hw_virtualpath *vpath;

	vxge_trace();

	vpath = vdev->vpath.vpathh;

	if (vpath) {
		if ((status = vxge_hw_vpath_reset(vpath)) == VXGE_HW_OK) {
			if (is_vxge_card_up(vdev) &&
				(status = vxge_hw_vpath_recover_from_reset(
					vpath))	!= VXGE_HW_OK) {
				vxge_debug(VXGE_ERR, "vxge_hw_vpath_recover_"
					"from_reset failed\n");
				return status;
			} else {
				status = __vxge_hw_vpath_reset_check(vpath);
				if (status != VXGE_HW_OK) {
					vxge_debug(VXGE_ERR,
					"__vxge_hw_vpath_reset_check error\n");
					return status;
				}
			}
		} else {
			vxge_debug(VXGE_ERR, "vxge_hw_vpath_reset failed\n");
			return status;
		}
	}
	return status;
}

/* close vpaths */
void vxge_close_vpaths(struct vxgedev *vdev)
{

	if (vdev->vpath.vpathh && vdev->vpath.is_open)
		vxge_hw_vpath_close(vdev->vpath.vpathh);

	vdev->vpath.is_open = 0;
	vdev->vpath.vpathh = NULL;
}

/* open vpaths */
int vxge_open_vpaths(struct vxgedev *vdev)
{
	enum vxge_hw_status status;
	struct __vxge_hw_device *hldev;

	hldev = (struct __vxge_hw_device  *)pci_get_drvdata(vdev->pdev);

	vdev->vpath.vpathh = &hldev->virtual_path;
	vdev->vpath.fifo.ndev = vdev->ndev;
	vdev->vpath.fifo.pdev = vdev->pdev;
	vdev->vpath.fifo.fifoh = &hldev->virtual_path.fifoh;
	vdev->vpath.ring.ndev = vdev->ndev;
	vdev->vpath.ring.pdev = vdev->pdev;
	vdev->vpath.ring.ringh = &hldev->virtual_path.ringh;

	status = vxge_hw_vpath_open(vdev->devh,	&vdev->vpath);
	if (status == VXGE_HW_OK) {
		vdev->vpath.is_open = 1;
	} else {
		vxge_debug(VXGE_ERR,
			"%s: vpath: %d failed to open "
			"with status: %d\n",
			vdev->ndev->name, vdev->vpath.device_id,
			status);
		vxge_close_vpaths(vdev);
		return status;
	}

	hldev->vpaths_deployed |= vxge_mBIT(vdev->vpath.vpathh->vp_id);

	return VXGE_HW_OK;
}

/** Functions that implement the iPXE driver API **/

/**
 * vxge_xmit
 * @skb : the socket buffer containing the Tx data.
 * @dev : device pointer.
 *
 * This function is the Tx entry point of the driver. Neterion NIC supports
 * certain protocol assist features on Tx side, namely  CSO, S/G, LSO.
 */
static int
vxge_xmit(struct net_device *dev, struct io_buffer *iobuf)
{
	struct vxge_fifo *fifo = NULL;
	struct vxgedev *vdev = NULL;
	struct __vxge_hw_fifo *fifoh;
	struct vxge_hw_fifo_txd *txdp;

	vxge_trace();

	vdev = (struct vxgedev *)netdev_priv(dev);

	if (!is_vxge_card_up(vdev)) {
		vxge_debug(VXGE_ERR,
			"%s: vdev not initialized\n", dev->name);
		return -EIO;
	}

	if (!netdev_link_ok(dev)) {
		vxge_debug(VXGE_ERR,
			"%s: Link down, transmit failed\n", dev->name);
		return -ENETDOWN;
	}

	fifo = &vdev->vpath.fifo;
	fifoh = fifo->fifoh;

	txdp = vxge_hw_fifo_free_txdl_get(fifoh);
	if (!txdp) {
		vxge_debug(VXGE_ERR,
			"%s: Out of tx descriptors\n", dev->name);
		return -ENOBUFS;
	}

	vxge_debug(VXGE_XMIT, "%s: %s:%d fifoh offset= %d\n",
		dev->name, __func__, __LINE__, fifoh->sw_offset);

	vxge_hw_fifo_txdl_buffer_set(fifoh, txdp, iobuf);

	vxge_hw_fifo_txdl_post(fifoh, txdp);

	return 0;
}

/*
 *  vxge_poll
 *  @ndev: net device pointer
 *
 *  This function acks the interrupt. It polls for rx packets
 *  and send to upper layer. It also checks for tx completion
 *  and frees iobs.
 */
static void vxge_poll(struct net_device *ndev)
{
	struct __vxge_hw_device  *hldev;
	struct vxgedev *vdev;

	vxge_debug(VXGE_POLL, "%s:%d \n", __func__, __LINE__);

	vdev = (struct vxgedev *)netdev_priv(ndev);
	hldev = (struct __vxge_hw_device *)pci_get_drvdata(vdev->pdev);

	if (!is_vxge_card_up(vdev))
		return;

	/* process alarm and acknowledge the interrupts */
	vxge_hw_device_begin_irq(hldev);

	vxge_hw_vpath_poll_tx(&hldev->virtual_path.fifoh);

	vxge_hw_vpath_poll_rx(&hldev->virtual_path.ringh);
}

/*
 * vxge_irq - enable or Disable interrupts
 *
 * @netdev   netdevice structure reference
 * @action   requested interrupt action
 */
static void vxge_irq(struct net_device *netdev __unused, int action)
{
	struct __vxge_hw_device  *hldev;
	struct vxgedev *vdev;

	vxge_debug(VXGE_INFO,
		"%s:%d action(%d)\n", __func__, __LINE__, action);

	vdev = (struct vxgedev *)netdev_priv(netdev);
	hldev = (struct __vxge_hw_device *)pci_get_drvdata(vdev->pdev);

	switch (action) {
	case DISABLE:
		vxge_hw_device_mask_all(hldev);
		break;
	default:
		vxge_hw_device_unmask_all(hldev);
		break;
	}
}

/**
 * vxge_open
 * @dev: pointer to the device structure.
 *
 * This function is the open entry point of the driver. It mainly calls a
 * function to allocate Rx buffers and inserts them into the buffer
 * descriptors and then enables the Rx part of the NIC.
 * Return value: '0' on success and an appropriate (-)ve integer as
 * defined in errno.h file on failure.
 */
int
vxge_open(struct net_device *dev)
{
	enum vxge_hw_status status;
	struct vxgedev *vdev;
	struct __vxge_hw_device *hldev;
	int ret = 0;

	vxge_debug(VXGE_INFO, "%s: %s:%d\n",
			VXGE_DRIVER_NAME, __func__, __LINE__);

	vdev = (struct vxgedev *)netdev_priv(dev);
	hldev = (struct __vxge_hw_device *)pci_get_drvdata(vdev->pdev);

	/* make sure you have link off by default every time Nic is
	 * initialized */
	netdev_link_down(dev);

	/* Open VPATHs */
	status = vxge_open_vpaths(vdev);
	if (status != VXGE_HW_OK) {
		vxge_debug(VXGE_ERR, "%s: fatal: Vpath open failed\n",
				VXGE_DRIVER_NAME);
		ret = -EPERM;
		goto out0;
	}

	vdev->mtu = VXGE_HW_DEFAULT_MTU;
	/* set initial mtu before enabling the device */
	status = vxge_hw_vpath_mtu_set(vdev->vpath.vpathh, vdev->mtu);
	if (status != VXGE_HW_OK) {
		vxge_debug(VXGE_ERR,
			"%s: fatal: can not set new MTU\n", dev->name);
		ret = -EPERM;
		goto out2;
	}
	vxge_debug(VXGE_INFO,
		"%s: MTU is %d\n", vdev->ndev->name, vdev->mtu);

	set_bit(__VXGE_STATE_CARD_UP, vdev->state);

	wmb();

	if (vxge_hw_device_link_state_get(vdev->devh) == VXGE_HW_LINK_UP) {
		netdev_link_up(vdev->ndev);
		vxge_debug(VXGE_INFO, "%s: Link Up\n", vdev->ndev->name);
	}

	vxge_hw_device_intr_enable(hldev);

	vxge_hw_vpath_enable(vdev->vpath.vpathh);
	wmb();
	vxge_hw_vpath_rx_doorbell_init(vdev->vpath.vpathh);

	goto out0;

out2:
	vxge_close_vpaths(vdev);
out0:
	vxge_debug(VXGE_INFO, "%s: %s:%d  Exiting...\n",
				dev->name, __func__, __LINE__);
	return ret;
}

/**
 * vxge_close
 * @dev: device pointer.
 *
 * This is the stop entry point of the driver. It needs to undo exactly
 * whatever was done by the open entry point, thus it's usually referred to
 * as the close function.Among other things this function mainly stops the
 * Rx side of the NIC and frees all the Rx buffers in the Rx rings.
 * Return value: '0' on success and an appropriate (-)ve integer as
 * defined in errno.h file on failure.
 */
static void vxge_close(struct net_device *dev)
{
	struct vxgedev *vdev;
	struct __vxge_hw_device *hldev;

	vxge_debug(VXGE_INFO, "%s: %s:%d\n",
		dev->name, __func__, __LINE__);

	vdev = (struct vxgedev *)netdev_priv(dev);
	hldev = (struct __vxge_hw_device *)pci_get_drvdata(vdev->pdev);

	if (!is_vxge_card_up(vdev))
		return;

	clear_bit(__VXGE_STATE_CARD_UP, vdev->state);

	vxge_hw_vpath_set_zero_rx_frm_len(hldev);

	netdev_link_down(vdev->ndev);
	vxge_debug(VXGE_INFO, "%s: Link Down\n", vdev->ndev->name);

	/* Note that at this point xmit() is stopped by upper layer */
	vxge_hw_device_intr_disable(hldev);

	/* Multi function shares INTA, hence we should
	 * leave it in enabled state
	 */
	if (is_mf(hldev->hw_info.function_mode))
		vxge_hw_device_unmask_all(hldev);

	vxge_reset_all_vpaths(vdev);

	vxge_close_vpaths(vdev);

	vxge_debug(VXGE_INFO,
		"%s: %s:%d  Exiting...\n", dev->name, __func__, __LINE__);
}

static struct net_device_operations vxge_operations;

int vxge_device_register(struct __vxge_hw_device *hldev,
				struct vxgedev **vdev_out)
{
	struct net_device *ndev;
	struct vxgedev *vdev;
	int ret = 0;

	*vdev_out = NULL;

	ndev = alloc_etherdev(sizeof(struct vxgedev));
	if (ndev == NULL) {
		vxge_debug(VXGE_ERR, "%s : device allocation failed\n",
				__func__);
		ret = -ENODEV;
		goto _out0;
	}

	vxge_debug(VXGE_INFO, "%s:%d  netdev registering\n",
		__func__, __LINE__);
	vdev = netdev_priv(ndev);
	memset(vdev, 0, sizeof(struct vxgedev));

	vdev->ndev = ndev;
	vdev->devh = hldev;
	vdev->pdev = hldev->pdev;

	ndev->dev = &vdev->pdev->dev;
	/* Associate vxge-specific network operations operations with
	 * generic network device layer */
	netdev_init(ndev, &vxge_operations);

	memcpy(ndev->hw_addr,
		(u8 *)hldev->hw_info.mac_addrs[hldev->first_vp_id], ETH_ALEN);

	if (register_netdev(ndev)) {
		vxge_debug(VXGE_ERR, "%s : device registration failed!\n",
			__func__);
		ret = -ENODEV;
		goto _out2;
	}

	/* Leave link state as off at this point, when the link change
	 * interrupt comes the state will be automatically changed to
	 * the right state.
	 */

	vxge_debug(VXGE_INFO, "%s: Ethernet device registered\n",
		VXGE_DRIVER_NAME);

	*vdev_out = vdev;

	return ret;
_out2:
	netdev_put(ndev);
_out0:
	return ret;
}

/*
 * vxge_device_unregister
 *
 * This function will unregister and free network device
 */
void
vxge_device_unregister(struct __vxge_hw_device *hldev)
{
	struct net_device *ndev;

	ndev = hldev->ndev;

	unregister_netdev(ndev);
	netdev_nullify(ndev);
	netdev_put(ndev);

	vxge_debug(VXGE_INFO, "%s: ethernet device unregistered\n",
				VXGE_DRIVER_NAME);
}

/**
 * vxge_probe
 * @pdev : structure containing the PCI related information of the device.
 * @id: List of PCI devices supported by the driver listed in vxge_id_table.
 * Description:
 * This function is called when a new PCI device gets detected and initializes
 * it.
 * Return value:
 * returns 0 on success and negative on failure.
 *
 */
static int
vxge_probe(struct pci_device *pdev)
{
	struct __vxge_hw_device  *hldev;
	enum vxge_hw_status status;
	int ret = 0;
	u64 vpath_mask = 0;
	struct vxgedev *vdev;
	int i;
	u8 revision, titan1;
	u32 function_mode;
	unsigned long mmio_start, mmio_len;
	void *bar0;
	struct vxge_hw_device_hw_info hw_info;
	struct vxge_hw_device_version *fw_version;

	vxge_debug(VXGE_INFO, "vxge_probe for device " PCI_FMT "\n",
			PCI_ARGS(pdev));

	pci_read_config_byte(pdev, PCI_REVISION, &revision);
	titan1 = is_titan1(pdev->device, revision);

	mmio_start = pci_bar_start(pdev, PCI_BASE_ADDRESS_0);
	mmio_len   = pci_bar_size(pdev, PCI_BASE_ADDRESS_0);
	vxge_debug(VXGE_INFO, "mmio_start: %#08lx, mmio_len: %#08lx\n",
			mmio_start, mmio_len);

	/* sets the bus master */
	adjust_pci_device(pdev);

	bar0 = ioremap(mmio_start, mmio_len);
	if (!bar0) {
		vxge_debug(VXGE_ERR,
			"%s : cannot remap io memory bar0\n", __func__);
		ret = -ENODEV;
		goto _exit0;
	}

	status = vxge_hw_device_hw_info_get(pdev, bar0, &hw_info);
	if (status != VXGE_HW_OK) {
		vxge_debug(VXGE_ERR,
			"%s: Reading of hardware info failed.\n",
			VXGE_DRIVER_NAME);
		ret = -EINVAL;
		goto _exit1;
	}

	if (hw_info.func_id != 0) {
		/* Non zero function, So do not load the driver */
		iounmap(bar0);
		pci_set_drvdata(pdev, NULL);
		return -EINVAL;
	}


	vpath_mask = hw_info.vpath_mask;
	if (vpath_mask == 0) {
		vxge_debug(VXGE_ERR,
			"%s: No vpaths available in device\n",
			VXGE_DRIVER_NAME);
		ret = -EINVAL;
		goto _exit1;
	}
	vxge_debug(VXGE_INFO,
		"%s:%d  Vpath mask = %llx\n", __func__, __LINE__,
		(unsigned long long)vpath_mask);

	fw_version = &hw_info.fw_version;
	/* fail the driver loading if firmware is incompatible */
	if ((fw_version->major != VXGE_CERT_FW_VER_MAJOR) ||
		(fw_version->minor < VXGE_CERT_FW_VER_MINOR)) {
		printf("%s: Adapter's current firmware version: %d.%d.%d\n",
			VXGE_DRIVER_NAME, fw_version->major,
			fw_version->minor, fw_version->build);

		printf("%s: Upgrade firmware to version %d.%d.%d\n",
			VXGE_DRIVER_NAME, VXGE_CERT_FW_VER_MAJOR,
			VXGE_CERT_FW_VER_MINOR,	VXGE_CERT_FW_VER_BUILD);

		ret = -EACCES;
		goto _exit1;
	}

	status = vxge_hw_device_initialize(&hldev, bar0, pdev, titan1);
	if (status != VXGE_HW_OK) {
		vxge_debug(VXGE_ERR,
			"Failed to initialize device (%d)\n", status);
			ret = -EINVAL;
			goto _exit1;
	}
	memcpy(&hldev->hw_info, &hw_info,
		sizeof(struct vxge_hw_device_hw_info));

	/* find the vpath id of the first available one */
	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++)
		if (vpath_mask & vxge_mBIT(i)) {
			hldev->first_vp_id = i;
			break;
		}
	/* if FCS stripping is not disabled in MAC fail driver load */
	if (vxge_hw_vpath_strip_fcs_check(hldev, vpath_mask) != VXGE_HW_OK) {
		vxge_debug(VXGE_ERR,
			"%s: FCS stripping is not disabled in MAC"
			" failing driver load\n", VXGE_DRIVER_NAME);
		ret = -EINVAL;
		goto _exit2;
	}

	/* Read function mode */
	status = vxge_hw_get_func_mode(hldev, &function_mode);
	if (status != VXGE_HW_OK)
		goto _exit2;

	hldev->hw_info.function_mode = function_mode;

	/* set private device info */
	pci_set_drvdata(pdev, hldev);

	if (vxge_device_register(hldev,	&vdev)) {
		ret = -EINVAL;
		goto _exit2;
	}

	/* set private HW device info */
	hldev->ndev = vdev->ndev;
	hldev->vdev = vdev;
	hldev->pdev = pdev;
	vdev->mtu = VXGE_HW_DEFAULT_MTU;
	vdev->bar0 = bar0;
	vdev->titan1 = titan1;
	/* Virtual Path count */
	vdev->vpath.device_id = hldev->first_vp_id;
	vdev->vpath.vdev = vdev;
	memcpy((u8 *)vdev->vpath.macaddr,
			(u8 *)hldev->hw_info.mac_addrs[hldev->first_vp_id],
			ETH_ALEN);

	hldev->hw_info.serial_number[VXGE_HW_INFO_LEN - 1] = '\0';
	hldev->hw_info.product_desc[VXGE_HW_INFO_LEN - 1] = '\0';
	hldev->hw_info.part_number[VXGE_HW_INFO_LEN - 1] = '\0';

	vxge_debug(VXGE_INFO, "%s: Neterion %s Server Adapter\n",
		VXGE_DRIVER_NAME, hldev->hw_info.product_desc);
	vxge_debug(VXGE_INFO, "%s: SERIAL NUMBER: %s\n",
		VXGE_DRIVER_NAME, hldev->hw_info.serial_number);
	vxge_debug(VXGE_INFO, "%s: PART NUMBER: %s\n",
		VXGE_DRIVER_NAME, hldev->hw_info.part_number);
	vxge_debug(VXGE_INFO, "%s: MAC ADDR: %s\n",
		VXGE_DRIVER_NAME, eth_ntoa(vdev->vpath.macaddr));
	vxge_debug(VXGE_INFO,
		"%s: Firmware version : %s Date : %s\n", VXGE_DRIVER_NAME,
		hldev->hw_info.fw_version.version,
		hldev->hw_info.fw_date.date);
	vxge_debug(VXGE_INFO, "%s: %s Enabled\n",
			VXGE_DRIVER_NAME, vxge_func_mode_names[function_mode]);

	vxge_debug(VXGE_INFO, "%s: %s:%d  Probe Exiting...\n",
		VXGE_DRIVER_NAME, __func__, __LINE__);

	return 0;

_exit2:
	vxge_hw_device_terminate(hldev);
_exit1:
	iounmap(bar0);
_exit0:
	pci_set_drvdata(pdev, NULL);
	printf("%s: WARNING!! Driver loading failed!!\n",
		VXGE_DRIVER_NAME);

	return ret;
}

/**
 * vxge_remove - Free the PCI device
 * @pdev: structure containing the PCI related information of the device.
 * Description: This function is called by the Pci subsystem to release a
 * PCI device and free up all resource held up by the device.
 */
static void
vxge_remove(struct pci_device *pdev)
{
	struct __vxge_hw_device  *hldev;
	struct vxgedev *vdev = NULL;
	struct net_device *ndev;

	vxge_debug(VXGE_INFO,
		"%s:%d\n", __func__, __LINE__);
	hldev = (struct __vxge_hw_device  *) pci_get_drvdata(pdev);
	if (hldev == NULL)
		return;

	ndev = hldev->ndev;
	vdev = netdev_priv(ndev);

	iounmap(vdev->bar0);

	vxge_device_unregister(hldev);

	vxge_debug(VXGE_INFO,
		"%s:%d  Device unregistered\n", __func__, __LINE__);

	vxge_hw_device_terminate(hldev);
	pci_set_drvdata(pdev, NULL);
}

/* vxge net device operations */
static struct net_device_operations vxge_operations = {
	.open           = vxge_open,
	.close          = vxge_close,
	.transmit       = vxge_xmit,
	.poll           = vxge_poll,
	.irq            = vxge_irq,
};

static struct pci_device_id vxge_main_nics[] = {
	/* If you change this, also adjust vxge_nics[] in vxge.c */
	PCI_ID(0x17d5, 0x5833, "vxge-x3100", "Neterion X3100 Series", 0),
};

struct pci_driver vxge_driver __pci_driver = {
	.ids = vxge_main_nics,
	.id_count = (sizeof(vxge_main_nics) / sizeof(vxge_main_nics[0])),
	.probe = vxge_probe,
	.remove = vxge_remove,
};
