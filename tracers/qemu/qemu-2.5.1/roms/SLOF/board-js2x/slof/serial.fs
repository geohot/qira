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


\ Serial console.  Enabled very early.
\ remember last console used
CREATE lastser 4 allot  0 lastser l!

\ On JS21, use serial port 2.  Detect Maui by looking at the SIO version.
20 siocfg@ f2 = IF 2f8 ELSE 3f8 THEN

: >serial  LITERAL + ;
: js21?	   -2f8 >serial 0= ;
: serial!  js21? IF 2dup 2f8 + io-c! THEN 3f8 + io-c! ;
: serial1@ 3f8 + io-c@ ;
: serial2@ 2f8 + io-c@ ;

: serial-init  0 1 serial!  0 2 serial!
               80 3 serial! d# 115200 swap / 0 serial!  0 1 serial!
               3 3 serial!  3 4 serial! ;
: serial-emit  BEGIN 5 serial1@ 20 and UNTIL  
 	       js21? IF BEGIN 5 serial2@ 20 and UNTIL THEN 0 serial! ;
: serial1-key? 5 serial1@ 1 and 0<> ;
: serial2-key? 5 serial2@ 1 and 0<> ;
: serial1-key  serial1-key? dup IF 0 serial1@ swap 0 lastser l! THEN ;
: serial2-key  serial2-key? dup IF 0 serial2@ swap 1 lastser l! THEN ;
: serial-key   BEGIN serial1-key dup IF ELSE js21? IF drop serial2-key THEN THEN UNTIL ;
: serial-key?  serial1-key? js21? IF serial2-key? or THEN ;

\ : serial-key   BEGIN 5 serial2@ 1 and UNTIL  0 serial2@ ;
\ : serial-key?  5 serial2@  1 and 0<> ;

d# 19200 serial-init
' serial-emit to emit
' serial-key  to key
' serial-key? to key?

( .( SLOF)
\ .(  has started execution, serial console @ ) 0 >serial .
