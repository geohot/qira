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

0 VALUE char-height
0 VALUE char-width
0 VALUE fontbytes

CREATE display-emit-buffer 20 allot

\ \\\\\\\\\\\\\\ Global Data

\ \\\\\\\\\\\\\\ Structure/Implementation Dependent Methods

\ \\\\\\\\\\\\\\ Implementation Independent Methods (Depend on Previous)
\ *
\ *
defer dis-old-emit
' emit behavior to dis-old-emit

: display-write terminal-write ;
: display-emit dup dis-old-emit display-emit-buffer tuck c! 1 terminal-write drop ;

\ \\\\\\\\\\\\\\ Exported Interface:
\ *
\ Generic device methods:
\ *


\ \\\\\\\\\\\\\\ Exported Interface:
\ *
\ IEEE 1275 : display device driver initialization
\ *
: is-install ( 'open -- )
	s" defer vendor-open to vendor-open" eval
	s" : open deadbeef vendor-open dup deadbeef = IF drop true ELSE nip THEN ;" eval
	s" defer write ' display-write to write" eval
	s" : draw-logo ['] draw-logo CATCH IF 2drop 2drop THEN ;" eval
	s" : reset-screen ['] reset-screen CATCH drop ;" eval
;

: is-remove ( 'close -- )
	s" defer close to close" eval
;

: is-selftest ( 'selftest -- )
	s" defer selftest to selftest" eval
;


STRUCT
	cell FIELD font>addr
	cell FIELD font>width
	cell FIELD font>height
	cell FIELD font>advance
	cell FIELD font>min-char
	cell FIELD font>#glyphs
CONSTANT /font

CREATE default-font-ctrblk /font allot default-font-ctrblk
	dup font>addr 0 swap !
	dup font>width 8 swap !
	dup font>height -10 swap !
	dup font>advance 1 swap !
	dup font>min-char 20 swap !
	font>#glyphs 7f swap !

: display-default-font ( str len -- )
   romfs-lookup dup 0= IF drop EXIT THEN
   600 <> IF ." Only support 60x8x16 fonts ! " drop EXIT THEN
   default-font-ctrblk font>addr !
;

s" default-font.bin" display-default-font

\ \\\\\\\\\\\\\\ Implementation Independent Methods (Depend on Previous)
\ *
\ *


\ \\\\\\\\\\\\\\ Exported Interface:
\ *
\ Generic device methods:
\ *
: .scan-lines ( height -- scanlines ) dup 0>= IF 1- ELSE negate THEN ;


\ \\\\\\\\\\\\\\ Exported Interface:
\ *
\ *

: set-font ( addr width height advance min-char #glyphs -- )
   default-font-ctrblk /font + /font 0
   DO
      1 cells - dup >r ! r> 1 cells
   +LOOP drop
   default-font-ctrblk dup font>height @ abs to char-height
   dup font>width @ to char-width font>advance @ to fontbytes
;

: >font ( char -- addr )
   dup default-font-ctrblk dup >r font>min-char @ dup r@ font>#glyphs + within
   IF
      r@ font>min-char @ -
      r@ font>advance @ * r@ font>height @ .scan-lines *
      r> font>addr @ +
   ELSE
      drop r> font>addr @
   THEN
;

: default-font ( -- addr width height advance min-char #glyphs )
    default-font-ctrblk /font 0 DO dup cell+ >r @ r> 1 cells +LOOP drop
;

