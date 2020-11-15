new-device

VALUE sudev

s" slofdev.fs" included
sudev slof-dev>port l@ dup set-unit encode-phys " reg" property
sudev slof-dev>udev @ VALUE udev

s" hub" device-name

s" dev-parent-calls.fs" included

1 encode-int s" #address-cells" property
0 encode-int s" #size-cells" property
: decode-unit  1 hex-decode-unit ;
: encode-unit  1 hex-encode-unit ;

: usb-hub-init ( usbdev -- true | false )
    udev USB-HUB-INIT
;

: open   ( -- true | false )
    TRUE
;

: close
;

."     USB HUB " cr
usb-hub-init drop

finish-device
