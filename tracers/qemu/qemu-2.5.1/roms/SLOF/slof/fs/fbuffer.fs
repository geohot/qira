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

#include "terminal.fs"
#include "display.fs"

\ \\\\\\\\\\\\\\ Global Data

0 VALUE frame-buffer-adr
0 VALUE screen-height
0 VALUE screen-width
0 VALUE screen-depth
0 VALUE screen-line-bytes
0 VALUE window-top
0 VALUE window-left

0 VALUE .sc

: screen-#rows  ( -- rows )
   .sc IF
      screen-height char-height /
    ELSE
      true to .sc
      s" screen-#rows" eval
      false to .sc
    THEN
;

: screen-#columns ( -- columns )
   .sc IF
      screen-width char-width /
   ELSE
      true to .sc
      s" screen-#columns" eval
      false to .sc
   THEN
;

\ \\\\\\\\\\\\\\ Structure/Implementation Dependent Methods


\ \\\\\\\\\\\\\\ Implementation Independent Methods (Depend on Previous)
\ *
\ *

: fb8-background inverse? ;
: fb8-foreground inverse? invert ;

: fb8-lines2bytes ( #lines -- #bytes ) char-height * screen-line-bytes * ;
: fb8-columns2bytes ( #columns -- #bytes ) char-width * screen-depth * ;
: fb8-line2addr ( line# -- addr )
	char-height * window-top + screen-line-bytes *
	frame-buffer-adr + window-left screen-depth * +
;

: fb8-erase-block ( addr len ) fb8-background rfill ;


0 VALUE .ab
CREATE bitmap-buffer 400 4 * allot

: active-bits ( -- new ) .ab dup 8 > IF 8 - to .ab 8 ELSE
		char-width to .ab ?dup 0= IF recurse THEN
	THEN ;

: fb8-char2bitmap ( font-height font-addr -- bitmap-buffer )
	bitmap-buffer >r
	char-height rot 0> IF r> char-width 2dup fb8-erase-block + >r 1- THEN

	r> -rot char-width to .ab
	( fb-addr font-addr font-height )
	fontbytes * bounds ?DO
		i c@ active-bits 0 ?DO
			dup 80 and IF fb8-foreground ELSE fb8-background THEN
			( fb-addr fbyte colr ) 2 pick ! 1 lshift
			swap screen-depth + swap
		LOOP drop
	LOOP drop
	bitmap-buffer
;

\ \\\\\\\\\\\\\\ Exported Interface:
\ *
\ * IEEE 1275: Frame buffer support routines
\ *

: fb8-draw-logo ( line# addr width height -- ) ." fb8-draw-logo ( " .s ."  )" cr
	2drop 2drop
;

: fb8-toggle-cursor ( -- )
	line# fb8-line2addr column# fb8-columns2bytes +
	char-height 2 - screen-line-bytes * +
	2 0 ?DO
		dup char-width screen-depth * invert-region
		screen-line-bytes +
	LOOP drop
;

: fb8-draw-character ( char -- )
    >r default-font over + r@ -rot between IF
	2swap 3drop r> >font fb8-char2bitmap ( bitmap-buf )
	line# fb8-line2addr column# fb8-columns2bytes + ( bitmap-buf fb-addr )
	char-height 0 ?DO
		2dup char-width screen-depth * mrmove
		screen-line-bytes + >r char-width screen-depth * + r>
	LOOP 2drop
    ELSE 2drop r> 3drop THEN
;

: fb8-insert-lines ( n -- )
	fb8-lines2bytes >r line# fb8-line2addr dup dup r@ +
	#lines line# - fb8-lines2bytes r@ - rmove
	r> fb8-erase-block
;

: fb8-delete-lines ( n -- )
	fb8-lines2bytes >r line# fb8-line2addr dup dup r@ + swap
	#lines fb8-lines2bytes r@ - dup >r rmove
	r> + r> fb8-erase-block
;

: fb8-insert-characters ( n -- )
	line# fb8-line2addr column# fb8-columns2bytes + >r
	#columns column# - 2dup >= IF
		nip dup 0> IF fb8-columns2bytes r> ELSE r> 2drop EXIT THEN
	ELSE
		fb8-columns2bytes swap fb8-columns2bytes tuck -
		over r@ tuck + rot char-height 0 ?DO
			3dup rmove
			-rot screen-line-bytes tuck + -rot + swap rot
		LOOP
		3drop r>
	THEN
	char-height 0 ?DO
		dup 2 pick fb8-erase-block screen-line-bytes +
	LOOP
	2drop
;

: fb8-delete-characters ( n -- )
	line# fb8-line2addr column# fb8-columns2bytes + >r
	#columns column# - 2dup >= IF
		nip dup 0> IF fb8-columns2bytes r> ELSE r> 2drop EXIT THEN
	ELSE
		fb8-columns2bytes swap fb8-columns2bytes tuck -
		over r@ + 2dup + r> swap >r rot char-height 0 ?DO
			3dup rmove
			-rot screen-line-bytes tuck + -rot + swap rot
		LOOP
		3drop r> over -
	THEN
	char-height 0 ?DO
		dup 2 pick fb8-erase-block screen-line-bytes +
	LOOP
	2drop
;

: fb8-reset-screen ( -- ) ( Left as no-op by design ) ;

: fb8-erase-screen ( -- )
	frame-buffer-adr screen-height screen-line-bytes * fb8-erase-block
;

: fb8-invert-screen ( -- )
	frame-buffer-adr screen-height screen-line-bytes * invert-region
;

: fb8-blink-screen ( -- ) fb8-invert-screen fb8-invert-screen ;

: fb8-install ( width height #columns #lines -- )
	1 to screen-depth
	2swap  to screen-height  to screen-width
	screen-width to screen-line-bytes
	screen-#rows min to #lines
	screen-#columns min to #columns
	screen-height char-height #lines * - 2/ to window-top
	screen-width char-width #columns * - 2/ to window-left
	['] fb8-toggle-cursor to toggle-cursor
	['] fb8-draw-character to draw-character
	['] fb8-insert-lines to insert-lines
	['] fb8-delete-lines to delete-lines
	['] fb8-insert-characters to insert-characters
	['] fb8-delete-characters to delete-characters
	['] fb8-erase-screen to erase-screen
	['] fb8-blink-screen to blink-screen
	['] fb8-invert-screen to invert-screen
	['] fb8-reset-screen to reset-screen
	['] fb8-draw-logo to draw-logo
;

: fb-install  ( width height #columns #lines depth -- )
	>r
	fb8-install
	r> to screen-depth
	screen-width screen-depth * to screen-line-bytes
;


\ Install display related FCODE evaluator tokens
: fb8-set-tokens  ( -- )
	['] is-install        0 11C set-token
	['] is-remove         0 11D set-token
	['] is-selftest       0 11E set-token

	['] #lines            0 150 set-token
	['] #columns          0 151 set-token
	['] line#             0 152 set-token
	['] column#           0 153 set-token
	['] inverse?          0 154 set-token
	['] inverse-screen?   0 155 set-token
	['] draw-character    0 157 set-token
	['] reset-screen      0 158 set-token
	['] toggle-cursor     0 159 set-token
	['] erase-screen      0 15A set-token
	['] blink-screen      0 15B set-token
	['] invert-screen     0 15C set-token
	['] insert-characters 0 15D set-token
	['] delete-characters 0 15E set-token
	['] insert-lines      0 15F set-token
	['] delete-lines      0 160 set-token
	['] draw-logo         0 161 set-token
	['] frame-buffer-adr  0 162 set-token
	['] screen-height     0 163 set-token
	['] screen-width      0 164 set-token
	['] window-top        0 165 set-token
	['] window-left       0 166 set-token
	\ ['] foreground-color  0 168 set-token  \ 16-color extension - n/a
	\ ['] background-color  0 169 set-token  \ 16-color extension - n/a
	['] default-font      0 16A set-token
	['] set-font          0 16B set-token
	['] char-height       0 16C set-token
	['] char-width        0 16D set-token
	['] >font             0 16E set-token
	['] fontbytes         0 16F set-token

	['] fb8-draw-character    0 180 set-token
	['] fb8-reset-screen      0 181 set-token
	['] fb8-toggle-cursor     0 182 set-token
	['] fb8-erase-screen      0 183 set-token
	['] fb8-blink-screen      0 184 set-token
	['] fb8-invert-screen     0 185 set-token
	['] fb8-insert-characters 0 186 set-token
	['] fb8-delete-characters 0 187 set-token
	['] fb8-insert-lines      0 188 set-token
	['] fb8-delete-lines      0 189 set-token
	['] fb8-draw-logo         0 18A set-token
	['] fb8-install           0 18B set-token
;
fb8-set-tokens


\ \\\\\\\\\\\\ Debug Stuff \\\\\\\\\\\\\\\\

: fb8-dump-bitmap cr char-height 0 ?do char-width 0 ?do dup c@ if ." @" else ." ." then 1+ loop cr loop drop ;

: fb8-dump-char >font -b swap fb8-char2bitmap fb8-dump-bitmap ;
