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


\ =============================================================================
\ =============================================================================


\ The deblocker.  Allows block devices to be used as a (seekable) byte device.

s" deblocker" device-name

INSTANCE VARIABLE offset
INSTANCE VARIABLE block-size
INSTANCE VARIABLE max-transfer
INSTANCE VARIABLE my-block
INSTANCE VARIABLE adr
INSTANCE VARIABLE len
INSTANCE VARIABLE fail-count

: open
  s" block-size" ['] $call-parent CATCH IF 2drop false EXIT THEN
  block-size !
  s" max-transfer" ['] $call-parent CATCH IF 2drop false EXIT THEN
  max-transfer !
  block-size @ alloc-mem my-block !
  0 offset !
  true ;
: close  my-block @ block-size @ free-mem ;

: seek ( lo hi -- status ) \ XXX: perhaps we should fail if the underlying
                           \      device would fail at this offset
  lxjoin offset !  0 ;
: block+remainder ( -- block# remainder )  offset @ block-size @ u/mod swap ;
: read-blocks ( addr block# #blocks -- actual )  s" read-blocks" $call-parent ;
: read ( addr len -- actual )
  dup >r  len ! adr !
  \ First, handle a partial block at the start.
  block+remainder dup IF ( block# offset-in-block )
  >r my-block @ swap 1 read-blocks drop
  my-block @ r@ + adr @ block-size @ r> - len @ min dup >r move
  r> dup negate len +! dup adr +! offset +! ELSE 2drop THEN

  \ Now, in a loop read max. max-transfer sized runs of whole blocks.
  0 fail-count !
  BEGIN len @ block-size @ >= WHILE
    adr @ block+remainder drop len @ max-transfer @ min block-size @ / read-blocks
    dup 0= IF
      1 fail-count +!
      fail-count @ 5 >= IF r> drop EXIT THEN
    ELSE
      0 fail-count !
    THEN
    block-size @ * dup negate len +! dup adr +! offset +!
  REPEAT

  \ And lastly, handle a partial block at the end.
  len @ IF my-block @ block+remainder drop 1 read-blocks drop
  my-block @ adr @ len @ move THEN

  r> ;
