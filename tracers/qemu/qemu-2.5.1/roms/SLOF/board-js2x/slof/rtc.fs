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
\ PC87417.pdf
\ moved the RTC initialisation from the device tree to a much earlier point
\ so that the RTC can be accessed before device tree is generated

\ Enable the RTC, set its address at 1070
\ see PC87417.pdf page 39 (chapter 3.2.3)
10 7 siocfg!
1 30 siocfg!
1070 wbsplit nip dup 60 siocfg! 62 siocfg!

: rtc@  ( offset -- value )
   1070 io-c! 1071 io-c@
;

: rtc!  ( value offset -- )
   1070 io-c! 1071 io-c!
;

\ Set sane configuration; BCD mode is required by Linux.
\ PC87417.pdf page 153 (chapter 8.3.13) - RTC Control Register A
\ 20 - Divider Chain Control = Normal Operation
20 0a rtc!
\ PC87417.pdf page 155 (chapter 8.3.14) - RTC Control Register B
\ 02 - 24-hour format enabled
02 0b rtc!
\ PC87417.pdf page 156 (chapter 8.3.15) - RTC Control Register C
00 0c rtc!

\ read from the rtc and do the bcd-to-bin conversion
: rtc-bin@  ( offset -- value )
   rtc@ bcd-to-bin
;

\ to be compatible with the cell boards we provide a .date word
\ .date prints the current date and time on the firmware prompt
: .date  ( -- )
   0 rtc-bin@  ( seconds )
   2 rtc-bin@
   4 rtc-bin@
   7 rtc-bin@
   8 rtc-bin@  ( seconds minutes hours day month )
   9 rtc-bin@ d# 1900 + dup d# 1970 <  IF  d# 100 +  THEN
   decimal 4 0.r 2d emit 2 0.r 2d emit 2 0.r space
   2 0.r 3a emit 2 0.r 3a emit 2 0.r hex
;
