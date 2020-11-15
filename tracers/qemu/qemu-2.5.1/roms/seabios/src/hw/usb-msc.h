#ifndef __USB_MSC_H
#define __USB_MSC_H

// usb-msc.c
struct disk_op_s;
int usb_cmd_data(struct disk_op_s *op, void *cdbcmd, u16 blocksize);
struct usbdevice_s;
int usb_msc_setup(struct usbdevice_s *usbdev);

#endif // ush-msc.h
