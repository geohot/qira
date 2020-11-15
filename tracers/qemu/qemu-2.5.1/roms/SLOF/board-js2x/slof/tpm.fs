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


\ Atmel TPM.

new-device   500 1 set-unit

s" tpm" 2dup device-name device-type

s" AT97SC3201" compatible

\ 2 bytes of ISA I/O space
my-unit encode-int rot encode-int+ 2 encode-int+ s" reg" property

: >tpm  4e io-c! ;
: tpm@  >tpm 4f io-c@ ;
: tpm!  >tpm 4f io-c! ;

: dump-tpm  11 0 DO cr i 2 .r space i tpm@ 2 0.r LOOP ;

my-address wbsplit 9 tpm! 8 tpm! \ set base address
0 a tpm! \ disable serint

\ Now we need to execute TPM_Startup.
CREATE startup-cmd
0 c, c1 c,
0 c, 0 c, 0 c, c c,
0 c, 0 c, 0 c, 99 c, \ TPM_ORD_Startup
0 c, 1 c, \ TCPA_ST_CLEAR

: send ( addr len -- )  bounds ?DO i c@ 500 io-c! LOOP ;
: wait-for-ready ( -- )  BEGIN 501 io-c@ 3 and 2 = UNTIL ;
: recv-verbose  ( -- )
   cr ." TPM result: "
   500 io-c@ 2 0.r 500 io-c@ 2 0.r space
   500 io-c@ 500 io-c@ 500 io-c@ 500 io-c@ 
   bljoin lbflip 6 - dup 8 0.r space 0
   ?DO  500 io-c@ .  LOOP
;

: recv ( -- )
   500 io-c@ drop 500 io-c@ drop
   500 io-c@ 500 io-c@ 500 io-c@ 500 io-c@
   bljoin lbflip 6 - 0
   ?DO  500 io-c@ drop  LOOP
;

startup-cmd c send  wait-for-ready  recv

: open  true ;
: close ;

finish-device
