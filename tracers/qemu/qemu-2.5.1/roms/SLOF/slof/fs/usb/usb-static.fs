\ *****************************************************************************
\ * Copyright (c) 2004, 2011, 2013 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ Load dev hci
: load-dev-hci ( num name-str name-len )
   s" dev-hci.fs" INCLUDED
;

0 VALUE ohci-init
0 VALUE ehci-init
0 VALUE xhci-init
0 VALUE usb-alias-num

: get-usb-alias-num
  usb-alias-num dup 1+ to usb-alias-num
;

\ create a new ohci device alias for the current node
: set-ohci-alias  (  -- )
    1 to ohci-init 
    get-usb-alias-num       ( num )
    s" ohci" 1 load-dev-hci
;

\ create a new ehci device alias for the current node
: set-ehci-alias  (  -- )
    1 to ehci-init
    get-usb-alias-num       ( num )
    s" ehci" 2 load-dev-hci
;

\ create a new xhci device alias for the current node
: set-xhci-alias  (  -- )
    1 to xhci-init 
    get-usb-alias-num       ( num )
    s" xhci" 3 load-dev-hci
;

: usb-enumerate ( hcidev -- )
    USB-HCD-INIT
;

: usb-scan ( -- )
    ." Scanning USB " cr
    ohci-init 1 = IF USB-OHCI-REGISTER THEN
    ehci-init 1 = IF USB-EHCI-REGISTER THEN
    xhci-init 1 = IF USB-XHCI-REGISTER THEN

    usb-alias-num 0 ?DO
	" usb" i $cathex find-device
	" get-hci-dev" get-node find-method
	IF
	    execute usb-enumerate
	ELSE
	    ." get-base-address method not found for usb@" i . 
	    ."  Device type: "
	    " device_type" get-node get-property 0= IF decode-string type cr 2drop THEN
	THEN
    LOOP
    0 set-node     \ FIXME Setting it back
;
