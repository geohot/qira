// Code for handling USB Mass Storage Controller devices.
//
// Copyright (C) 2010  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_GLOBALFLAT
#include "block.h" // DTYPE_USB
#include "blockcmd.h" // cdb_read
#include "config.h" // CONFIG_USB_MSC
#include "malloc.h" // free
#include "output.h" // dprintf
#include "std/disk.h" // DISK_RET_SUCCESS
#include "string.h" // memset
#include "usb.h" // struct usb_s
#include "usb-msc.h" // usb_msc_setup
#include "util.h" // bootprio_find_usb

struct usbdrive_s {
    struct drive_s drive;
    struct usb_pipe *bulkin, *bulkout;
    int lun;
};


/****************************************************************
 * Bulk-only drive command processing
 ****************************************************************/

#define USB_CDB_SIZE 12

#define CBW_SIGNATURE 0x43425355 // USBC

struct cbw_s {
    u32 dCBWSignature;
    u32 dCBWTag;
    u32 dCBWDataTransferLength;
    u8 bmCBWFlags;
    u8 bCBWLUN;
    u8 bCBWCBLength;
    u8 CBWCB[16];
} PACKED;

#define CSW_SIGNATURE 0x53425355 // USBS

struct csw_s {
    u32 dCSWSignature;
    u32 dCSWTag;
    u32 dCSWDataResidue;
    u8 bCSWStatus;
} PACKED;

static int
usb_msc_send(struct usbdrive_s *udrive_gf, int dir, void *buf, u32 bytes)
{
    struct usb_pipe *pipe;
    if (dir == USB_DIR_OUT)
        pipe = GET_GLOBALFLAT(udrive_gf->bulkout);
    else
        pipe = GET_GLOBALFLAT(udrive_gf->bulkin);
    return usb_send_bulk(pipe, dir, buf, bytes);
}

// Low-level usb command transmit function.
int
usb_cmd_data(struct disk_op_s *op, void *cdbcmd, u16 blocksize)
{
    if (!CONFIG_USB_MSC)
        return 0;

    dprintf(16, "usb_cmd_data id=%p write=%d count=%d bs=%d buf=%p\n"
            , op->drive_gf, 0, op->count, blocksize, op->buf_fl);
    struct usbdrive_s *udrive_gf = container_of(
        op->drive_gf, struct usbdrive_s, drive);

    // Setup command block wrapper.
    u32 bytes = blocksize * op->count;
    struct cbw_s cbw;
    memset(&cbw, 0, sizeof(cbw));
    memcpy(cbw.CBWCB, cdbcmd, USB_CDB_SIZE);
    cbw.dCBWSignature = CBW_SIGNATURE;
    cbw.dCBWTag = 999; // XXX
    cbw.dCBWDataTransferLength = bytes;
    cbw.bmCBWFlags = cdb_is_read(cdbcmd, blocksize) ? USB_DIR_IN : USB_DIR_OUT;
    cbw.bCBWLUN = GET_GLOBALFLAT(udrive_gf->lun);
    cbw.bCBWCBLength = USB_CDB_SIZE;

    // Transfer cbw to device.
    int ret = usb_msc_send(udrive_gf, USB_DIR_OUT
                           , MAKE_FLATPTR(GET_SEG(SS), &cbw), sizeof(cbw));
    if (ret)
        goto fail;

    // Transfer data to/from device.
    if (bytes) {
        ret = usb_msc_send(udrive_gf, cbw.bmCBWFlags, op->buf_fl, bytes);
        if (ret)
            goto fail;
    }

    // Transfer csw info.
    struct csw_s csw;
    ret = usb_msc_send(udrive_gf, USB_DIR_IN
                       , MAKE_FLATPTR(GET_SEG(SS), &csw), sizeof(csw));
    if (ret)
        goto fail;

    if (!csw.bCSWStatus)
        return DISK_RET_SUCCESS;
    if (csw.bCSWStatus == 2)
        goto fail;

    if (blocksize)
        op->count -= csw.dCSWDataResidue / blocksize;
    return DISK_RET_EBADTRACK;

fail:
    // XXX - reset connection
    dprintf(1, "USB transmission failed\n");
    return DISK_RET_EBADTRACK;
}

static int
usb_msc_maxlun(struct usb_pipe *pipe)
{
    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE;
    req.bRequest = 0xfe;
    req.wValue = 0;
    req.wIndex = 0;
    req.wLength = 1;
    unsigned char maxlun;
    int ret = usb_send_default_control(pipe, &req, &maxlun);
    if (ret)
        return 0;
    return maxlun;
}

static int
usb_msc_lun_setup(struct usb_pipe *inpipe, struct usb_pipe *outpipe,
                  struct usbdevice_s *usbdev, int lun)
{
    // Allocate drive structure.
    struct usbdrive_s *drive = malloc_fseg(sizeof(*drive));
    if (!drive) {
        warn_noalloc();
        return -1;
    }
    memset(drive, 0, sizeof(*drive));
    if (usb_32bit_pipe(inpipe))
        drive->drive.type = DTYPE_USB_32;
    else
        drive->drive.type = DTYPE_USB;
    drive->bulkin = inpipe;
    drive->bulkout = outpipe;
    drive->lun = lun;

    int prio = bootprio_find_usb(usbdev, lun);
    int ret = scsi_drive_setup(&drive->drive, "USB MSC", prio);
    if (ret) {
        dprintf(1, "Unable to configure USB MSC drive.\n");
        free(drive);
        return -1;
    }
    return 0;
}

/****************************************************************
 * Setup
 ****************************************************************/

// Configure a usb msc device.
int
usb_msc_setup(struct usbdevice_s *usbdev)
{
    if (!CONFIG_USB_MSC)
        return -1;

    // Verify right kind of device
    struct usb_interface_descriptor *iface = usbdev->iface;
    if ((iface->bInterfaceSubClass != US_SC_SCSI &&
         iface->bInterfaceSubClass != US_SC_ATAPI_8070 &&
         iface->bInterfaceSubClass != US_SC_ATAPI_8020)
        || iface->bInterfaceProtocol != US_PR_BULK) {
        dprintf(1, "Unsupported MSC USB device (subclass=%02x proto=%02x)\n"
                , iface->bInterfaceSubClass, iface->bInterfaceProtocol);
        return -1;
    }

    // Find bulk in and bulk out endpoints.
    struct usb_pipe *inpipe = NULL, *outpipe = NULL;
    struct usb_endpoint_descriptor *indesc = usb_find_desc(
        usbdev, USB_ENDPOINT_XFER_BULK, USB_DIR_IN);
    struct usb_endpoint_descriptor *outdesc = usb_find_desc(
        usbdev, USB_ENDPOINT_XFER_BULK, USB_DIR_OUT);
    if (!indesc || !outdesc)
        goto fail;
    inpipe = usb_alloc_pipe(usbdev, indesc);
    outpipe = usb_alloc_pipe(usbdev, outdesc);
    if (!inpipe || !outpipe)
        goto fail;

    int maxlun = usb_msc_maxlun(usbdev->defpipe);
    int lun, pipesused = 0;
    for (lun = 0; lun < maxlun + 1; lun++) {
        int ret = usb_msc_lun_setup(inpipe, outpipe, usbdev, lun);
        if (!ret)
            pipesused = 1;
    }

    if (!pipesused)
        goto fail;

    return 0;
fail:
    dprintf(1, "Unable to configure USB MSC device.\n");
    usb_free_pipe(usbdev, inpipe);
    usb_free_pipe(usbdev, outpipe);
    return -1;
}
