\ *****************************************************************************
\ * Copyright (c) 2004, 2008 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/


\ National Semiconductor SIO.
\ See http://www.national.com/pf/PC/PC87417.html for the datasheet.

\ We use both serial ports, and the RTC.

\ See 3.7.5.
new-device   3f8 1 set-unit

s" serial" 2dup device-name device-type

\ Enable this UART.
3 7 siocfg!  1 30 siocfg!

\ 8 bytes of ISA I/O space
my-unit encode-int rot encode-int+ 8 encode-int+ s" reg" property
d# 19200 encode-int s" current-speed" property
44 encode-int 0 encode-int+ s" interrupts" property

: open  true ;
: close ;
: write ( adr len -- actual )  tuck type ;
: read  ( adr len -- actual )  0= IF drop 0 EXIT THEN
                               serial-key? 0= IF 0 swap c! -2 EXIT THEN
                               serial-key swap c! 1 ;

finish-device


new-device   2f8 1 set-unit

s" serial" 2dup device-name device-type

\ Enable this UART.
2 7 siocfg!  1 30 siocfg!

\ 8 bytes of ISA I/O space
my-unit encode-int rot encode-int+ 8 encode-int+ s" reg" property
d# 19200 encode-int s" current-speed" property
43 encode-int 0 encode-int+ s" interrupts" property

: open  true ;
: close ;
: write ( adr len -- actual )  tuck type ;
: read  ( adr len -- actual )  0= IF drop 0 EXIT THEN
                               serial-key? 0= IF 0 swap c! -2 EXIT THEN
                               serial-key swap c! 1 ;

finish-device



\ See the "Device Support Extensions" OF Recommended Practice document.
new-device   1070 1 set-unit

s" rtc" 2dup device-name device-type
\ Following is for Linux, to recognize this RTC:
s" pnpPNP,b00" compatible

: rtc!  my-space io-c!  my-space 1+ io-c! ;
: rtc@  my-space io-c!  my-space 1+ io-c@ ;

\ 10 bytes of ISA I/O space, at 1070.
my-unit encode-int rot encode-int+ 10 encode-int+ s" reg" property

: open   true ;
: close ;

\ XXX: dummy methods.
: get-time ( -- sec min hr day mth yr )  38 22 c 1 1 d# 1973 ;
: set-time ( sec min hr day mth yr -- )  3drop 3drop ;

finish-device
