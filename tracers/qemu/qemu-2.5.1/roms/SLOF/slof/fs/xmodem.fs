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


01 CONSTANT XM-SOH   \ Start of header
04 CONSTANT XM-EOT   \ End-of-transmission
06 CONSTANT XM-ACK   \ Acknowledge
15 CONSTANT XM-NAK   \ Neg. acknowledge

0 VALUE xm-retries   \ Retry count
0 VALUE xm-block#


\ *
\ * Internal function:
\ * wait <timeout> seconds for a new character
\ *
: xmodem-get-byte  ( timeout -- byte|-1 )
   d# 1000 *
   0 DO
      key? IF key UNLOOP EXIT THEN
      1 ms
   LOOP
   -1
;


\ *
\ * Internal function:
\ * Receive one XMODEM packet, check block number and check sum.
\ *
: xmodem-rx-packet  ( address -- success? )
   1 xmodem-get-byte    \ Get block number
   dup 0 < IF
      2drop false EXIT  \ Timeout
   THEN
   1 xmodem-get-byte    \ Get neg. block number
   dup 0 < IF
      3drop false EXIT  \ Timeout
   THEN
   rot 0                ( blk# ~blk# address chksum )
   80 0 DO
      1 xmodem-get-byte dup 0 < IF     ( blk# ~blk# address chksum byte )
         3drop 2drop UNLOOP FALSE EXIT
      THEN
      dup 3 pick c!            ( blk# ~blk# address chksum byte )
      + swap 1+ swap           ( blk# ~blk# address+1 chksum' )
   LOOP
   ( blk# ~blk# address chksum )
   \ Check sum:
   0ff and
   1 xmodem-get-byte <> IF
      \ CRC failed!
      3drop FALSE EXIT
   THEN
   drop                        ( blk# ~blk# )
   \ finally check if block numbers are ok:
   over xm-block# <> IF
      \ Wrong block number!
      2drop FALSE EXIT
   THEN                        ( blk# ~blk# )
   ff xor =
;


\ *
\ * Internal function:
\ * Load file to given address via XMODEM protocol
\ *
: (xmodem-load)  ( address -- bytes )
   1 to xm-block#
   0 to xm-retries
   dup
   BEGIN
      d# 10 xmodem-get-byte dup >r
      CASE
         XM-SOH OF
            dup xmodem-rx-packet IF
               \ A packet has been received successfully
               XM-ACK emit
               80 +                     ( start-addr next-addr  R: rx-byte )
               0 to xm-retries                    \ Reset retry count
               xm-block# 1+ ff and to xm-block#   \ Increase current block#
            ELSE
               \ Error while receiving packet
               XM-NAK emit
               xm-retries 1+ to xm-retries  \ Increase retry count
            THEN
         ENDOF
         XM-EOT OF
            XM-ACK emit
         ENDOF
         dup OF
            XM-NAK emit
            xm-retries 1+ to xm-retries  \ Increase retry count
         ENDOF
      ENDCASE
      r> XM-EOT =
      xm-retries d# 10 >= OR
   UNTIL                         ( start-address end-address )
   swap -                        ( bytes received )
;


\ *
\ * Load file to load-base via XMODEM protocol
\ *
: xmodem-load  ( -- bytes )
   cr ." Waiting for start of XMODEM upload..." cr
   get-load-base (xmodem-load)
;
