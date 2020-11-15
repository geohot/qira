new-device

VALUE sudev
false VALUE usb-keyb-debug?

s" slofdev.fs" included
sudev slof-dev>port l@ dup set-unit encode-phys " reg" property
sudev slof-dev>udev @ VALUE udev

s" usb-keyboard" device-name
s" keyboard" device-type
s" EN" encode-string s" language" property
s" keyboard" get-node node>path set-alias

s" dev-parent-calls.fs" included

0 VALUE open-count

: open   ( -- true | false )
    usb-keyb-debug? IF ." USB-KEYB: Opening (count is " open-count . ." )" cr THEN
    open-count 0= IF
	udev USB-HID-INIT 0= IF
	    ." USB keyboard setup failed " pwd cr false EXIT
	THEN
    THEN
    open-count 1 + to open-count
    true
;

: close
    usb-keyb-debug? IF ." USB-KEYB: Closing (count is " open-count . ." )" cr THEN
    open-count 0> IF
	open-count 1 - dup to open-count
	0= IF
	    my-phandle set-node
	    udev USB-HID-EXIT drop
	    0 set-node
	THEN
    THEN
;

\ method to check if a key is present in output buffer
\ used by 'term-io.fs'
: key-available? ( -- true|false )
    udev USB-KEY-AVAILABLE IF TRUE ELSE FALSE THEN
;

: read                     ( addr len -- actual )
    0= IF drop 0 EXIT THEN
    udev USB-READ-KEYB ?dup IF swap c! 1 ELSE 0 swap c! 0 then
;

."     USB Keyboard " cr
finish-device
