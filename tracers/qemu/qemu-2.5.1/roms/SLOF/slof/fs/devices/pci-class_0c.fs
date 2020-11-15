\ *****************************************************************************
\ * Copyright (c) 2004, 2011 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

s" serial bus [ " type my-space pci-class-name type s"  ]" type cr

my-space pci-device-generic-setup

STRUCT
    /n FIELD hcd>base
    /n FIELD hcd>type
    /n FIELD hcd>num
    /n FIELD hcd>ops
    /n FIELD hcd>priv
    /n FIELD hcd>nextaddr
CONSTANT /hci-dev

: usb-setup-hcidev ( num hci-dev -- )
    >r
    10 config-l@ F AND case
	0 OF 10 config-l@ translate-my-address ENDOF       \ 32-bit memory space
	4 OF                                               \ 64-bit memory space
	    14 config-l@ 20 lshift                         \ Read two bars
	    10 config-l@ OR translate-my-address
	ENDOF
    ENDCASE
    F not AND
    ( io-base ) r@ hcd>base !
    08 config-l@ 8 rshift  0000000F0 AND 4 rshift
    ( usb-type ) r@ hcd>type !
    ( usb-num )  r@ hcd>num !
    r> drop
;

\ Handle USB OHCI controllers:
: handle-usb-class  ( -- )
   \ set Memory Write and Invalidate Enable, SERR# Enable
   \ (see PCI 3.0 Spec Chapter 6.2.2 device control):
   4 config-w@ 110 or 4 config-w!
   pci-master-enable               \ set PCI Bus master bit and
   pci-mem-enable                  \ memory space enable for USB scan
;

\ Check PCI sub-class and interface type of Serial Bus Controller
\ to include the appropriate driver:
: handle-sbc-subclass  ( -- )
    my-space pci-class@ ffff and CASE         \ get PCI sub-class and interface
	0310 OF                      \ OHCI controller
	    handle-usb-class
	    set-ohci-alias
	ENDOF
	0320 OF                      \ EHCI controller
	    handle-usb-class
	    set-ehci-alias
	ENDOF
	0330 OF                      \ XHCI controller
	    handle-usb-class
	    set-xhci-alias
	ENDOF
   ENDCASE
;

handle-sbc-subclass
