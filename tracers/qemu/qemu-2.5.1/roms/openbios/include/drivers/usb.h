#ifndef USB_H
#define USB_H

int ob_usb_ohci_init(const char *path, uint32_t addr);
void ob_usb_hid_add_keyboard(const char *path);
int usb_exit(void);

#endif /* USB_H */
