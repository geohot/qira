#ifndef __USB_HID_H
#define __USB_HID_H

// usb-hid.c
struct usbdevice_s;
int usb_hid_setup(struct usbdevice_s *usbdev);
inline int usb_kbd_active(void);
inline int usb_kbd_command(int command, u8 *param);
inline int usb_mouse_active(void);
inline int usb_mouse_command(int command, u8 *param);
void usb_check_event(void);


/****************************************************************
 * hid flags
 ****************************************************************/

#define USB_INTERFACE_SUBCLASS_BOOT     1
#define USB_INTERFACE_PROTOCOL_KEYBOARD 1
#define USB_INTERFACE_PROTOCOL_MOUSE    2

#define HID_REQ_GET_REPORT              0x01
#define HID_REQ_GET_IDLE                0x02
#define HID_REQ_GET_PROTOCOL            0x03
#define HID_REQ_SET_REPORT              0x09
#define HID_REQ_SET_IDLE                0x0A
#define HID_REQ_SET_PROTOCOL            0x0B

#endif // ush-hid.h
