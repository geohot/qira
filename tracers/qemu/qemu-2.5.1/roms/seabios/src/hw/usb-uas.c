// Code for handling usb attached scsi devices.
//
// only usb 2.0 for now.
//
// once we have xhci driver with usb 3.0 support this must
// be updated to use usb3 streams so booting from usb3
// devices actually works.
//
// Authors:
//  Gerd Hoffmann <kraxel@redhat.com>
//
// based on usb-msc.c which is written by:
//  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "biosvar.h" // GET_GLOBALFLAT
#include "block.h" // DTYPE_USB
#include "blockcmd.h" // cdb_read
#include "config.h" // CONFIG_USB_UAS
#include "malloc.h" // free
#include "output.h" // dprintf
#include "std/disk.h" // DISK_RET_SUCCESS
#include "string.h" // memset
#include "usb.h" // struct usb_s
#include "usb-uas.h" // usb_uas_init
#include "util.h" // bootprio_find_usb

#define UAS_UI_COMMAND              0x01
#define UAS_UI_SENSE                0x03
#define UAS_UI_RESPONSE             0x04
#define UAS_UI_TASK_MGMT            0x05
#define UAS_UI_READ_READY           0x06
#define UAS_UI_WRITE_READY          0x07

#define UAS_PIPE_ID_COMMAND         0x01
#define UAS_PIPE_ID_STATUS          0x02
#define UAS_PIPE_ID_DATA_IN         0x03
#define UAS_PIPE_ID_DATA_OUT        0x04

typedef struct {
    u8    id;
    u8    reserved;
    u16   tag;
} PACKED  uas_ui_header;

typedef struct {
    u8    prio_taskattr;   /* 6:3 priority, 2:0 task attribute   */
    u8    reserved_1;
    u8    add_cdb_length;  /* 7:2 additional adb length (dwords) */
    u8    reserved_2;
    u8    lun[8];
    u8    cdb[16];
    u8    add_cdb[];
} PACKED  uas_ui_command;

typedef struct {
    u16   status_qualifier;
    u8    status;
    u8    reserved[7];
    u16   sense_length;
    u8    sense_data[18];
} PACKED  uas_ui_sense;

typedef struct {
    u16   add_response_info;
    u8    response_code;
} PACKED  uas_ui_response;

typedef struct {
    u8    function;
    u8    reserved;
    u16   task_tag;
    u8    lun[8];
} PACKED  uas_ui_task_mgmt;

typedef struct {
    uas_ui_header  hdr;
    union {
        uas_ui_command   command;
        uas_ui_sense     sense;
        uas_ui_task_mgmt task;
        uas_ui_response  response;
    };
} PACKED  uas_ui;

struct uasdrive_s {
    struct drive_s drive;
    struct usb_pipe *command, *status, *data_in, *data_out;
    int lun;
};

int
uas_cmd_data(struct disk_op_s *op, void *cdbcmd, u16 blocksize)
{
    if (!CONFIG_USB_UAS)
        return DISK_RET_EBADTRACK;

    struct uasdrive_s *drive_gf = container_of(
        op->drive_gf, struct uasdrive_s, drive);

    uas_ui ui;
    memset(&ui, 0, sizeof(ui));
    ui.hdr.id = UAS_UI_COMMAND;
    ui.hdr.tag = 0xdead;
    ui.command.lun[1] = GET_GLOBALFLAT(drive_gf->lun);
    memcpy(ui.command.cdb, cdbcmd, sizeof(ui.command.cdb));
    int ret = usb_send_bulk(GET_GLOBALFLAT(drive_gf->command),
                            USB_DIR_OUT, MAKE_FLATPTR(GET_SEG(SS), &ui),
                            sizeof(ui.hdr) + sizeof(ui.command));
    if (ret) {
        dprintf(1, "uas: command send fail");
        goto fail;
    }

    memset(&ui, 0xff, sizeof(ui));
    ret = usb_send_bulk(GET_GLOBALFLAT(drive_gf->status),
                        USB_DIR_IN, MAKE_FLATPTR(GET_SEG(SS), &ui), sizeof(ui));
    if (ret) {
        dprintf(1, "uas: status recv fail");
        goto fail;
    }

    switch (ui.hdr.id) {
    case UAS_UI_SENSE:
        goto have_sense;
    case UAS_UI_READ_READY:
        ret = usb_send_bulk(GET_GLOBALFLAT(drive_gf->data_in),
                            USB_DIR_IN, op->buf_fl, op->count * blocksize);
        if (ret) {
            dprintf(1, "uas: data read fail");
            goto fail;
        }
        break;
    case UAS_UI_WRITE_READY:
        ret = usb_send_bulk(GET_GLOBALFLAT(drive_gf->data_out),
                            USB_DIR_OUT, op->buf_fl, op->count * blocksize);
        if (ret) {
            dprintf(1, "uas: data write fail");
            goto fail;
        }
        break;
    default:
        dprintf(1, "uas: unknown status ui id %d", ui.hdr.id);
        goto fail;
    }

    memset(&ui, 0xff, sizeof(ui));
    ret = usb_send_bulk(GET_GLOBALFLAT(drive_gf->status),
                        USB_DIR_IN, MAKE_FLATPTR(GET_SEG(SS), &ui), sizeof(ui));
    if (ret) {
        dprintf(1, "uas: status recv fail");
        goto fail;
    }
    if (ui.hdr.id != UAS_UI_SENSE) {
        dprintf(1, "uas: expected sense ui, got ui id %d", ui.hdr.id);
        goto fail;
    }

have_sense:
    if (ui.sense.status == 0) {
        return DISK_RET_SUCCESS;
    }

fail:
    return DISK_RET_EBADTRACK;
}

static int
uas_lun_setup(struct usbdevice_s *usbdev,
              struct usb_pipe *command, struct usb_pipe *status,
              struct usb_pipe *data_in, struct usb_pipe *data_out,
              int lun)
{
    // Allocate drive structure.
    struct uasdrive_s *drive = malloc_fseg(sizeof(*drive));
    if (!drive) {
        warn_noalloc();
        return -1;
    }
    memset(drive, 0, sizeof(*drive));
    if (usb_32bit_pipe(data_in))
        drive->drive.type = DTYPE_UAS_32;
    else
        drive->drive.type = DTYPE_UAS;
    drive->command = command;
    drive->status = status;
    drive->data_in = data_in;
    drive->data_out = data_out;
    drive->lun = lun;

    int prio = bootprio_find_usb(usbdev, lun);
    int ret = scsi_drive_setup(&drive->drive, "USB UAS", prio);
    if (ret) {
        free(drive);
        return -1;
    }
    return 0;
}

int
usb_uas_setup(struct usbdevice_s *usbdev)
{
    if (!CONFIG_USB_UAS)
        return -1;

    // Verify right kind of device
    struct usb_interface_descriptor *iface = usbdev->iface;
    if (iface->bInterfaceSubClass != US_SC_SCSI ||
        iface->bInterfaceProtocol != US_PR_UAS) {
        dprintf(1, "Unsupported UAS device (subclass=%02x proto=%02x)\n"
                , iface->bInterfaceSubClass, iface->bInterfaceProtocol);
        return -1;
    }

    /* find & allocate pipes */
    struct usb_endpoint_descriptor *ep = NULL;
    struct usb_pipe *command = NULL;
    struct usb_pipe *status = NULL;
    struct usb_pipe *data_in = NULL;
    struct usb_pipe *data_out = NULL;
    u8 *desc = (u8*)iface;
    while (desc) {
        desc += desc[0];
        switch (desc[1]) {
        case USB_DT_ENDPOINT:
            ep = (void*)desc;
            break;
        case USB_DT_ENDPOINT_COMPANION:
            /* No support (yet) for usb3 streams */
            dprintf(1, "Superspeed UAS devices not supported (yet)\n");
            goto fail;
        case 0x24:
            switch (desc[2]) {
            case UAS_PIPE_ID_COMMAND:
                command = usb_alloc_pipe(usbdev, ep);
                break;
            case UAS_PIPE_ID_STATUS:
                status = usb_alloc_pipe(usbdev, ep);
                break;
            case UAS_PIPE_ID_DATA_IN:
                data_in = usb_alloc_pipe(usbdev, ep);
                break;
            case UAS_PIPE_ID_DATA_OUT:
                data_out = usb_alloc_pipe(usbdev, ep);
                break;
            default:
                goto fail;
            }
            break;
        default:
            desc = NULL;
            break;
        }
    }
    if (!command || !status || !data_in || !data_out)
        goto fail;

    /* TODO: send REPORT LUNS.  For now, only LUN 0 is recognized.  */
    int ret = uas_lun_setup(usbdev, command, status, data_in, data_out, 0);
    if (ret < 0) {
        dprintf(1, "Unable to configure UAS drive.\n");
        goto fail;
    }

    return 0;

fail:
    usb_free_pipe(usbdev, command);
    usb_free_pipe(usbdev, status);
    usb_free_pipe(usbdev, data_in);
    usb_free_pipe(usbdev, data_out);
    return -1;
}
