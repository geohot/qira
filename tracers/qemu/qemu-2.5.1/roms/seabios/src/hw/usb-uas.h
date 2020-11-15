#ifndef __USB_UAS_H
#define __USB_UAS_H

struct disk_op_s;
int uas_cmd_data(struct disk_op_s *op, void *cdbcmd, u16 blocksize);
struct usbdevice_s;
int usb_uas_setup(struct usbdevice_s *usbdev);

#endif /* __USB_UAS_H */
