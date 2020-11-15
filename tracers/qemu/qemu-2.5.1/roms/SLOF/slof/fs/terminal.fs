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

\ \\\\\\\\\\\\\\ Global Data

0 VALUE line#
0 VALUE column#
false VALUE inverse?
false VALUE inverse-screen?
18 VALUE #lines
50 VALUE #columns

false VALUE cursor
false VALUE saved-cursor


\ \\\\\\\\\\\\\\ Structure/Implementation Dependent Methods

defer draw-character	\ 2B inited by display driver
defer reset-screen	\ 2B inited by display driver
defer toggle-cursor	\ 2B inited by display driver
defer erase-screen	\ 2B inited by display driver
defer blink-screen	\ 2B inited by display driver
defer invert-screen	\ 2B inited by display driver
defer insert-characters	\ 2B inited by display driver
defer delete-characters	\ 2B inited by display driver
defer insert-lines	\ 2B inited by display driver
defer delete-lines	\ 2B inited by display driver
defer draw-logo		\ 2B inited by display driver

: nop-toggle-cursor ( nop ) ;
' nop-toggle-cursor to toggle-cursor

\ \\\\\\\\\\\\\\ Implementation Independent Methods (Depend on Previous)
\ *
\ *
: (cursor-off) ( -- ) cursor dup to saved-cursor
	IF toggle-cursor false to cursor THEN ;
: (cursor-on) ( -- ) cursor dup to saved-cursor
	0= IF toggle-cursor true to cursor THEN ;
: restore-cursor ( -- ) saved-cursor dup cursor
	<> IF toggle-cursor to cursor ELSE drop THEN ;

' (cursor-off) to cursor-off
' (cursor-on) to cursor-on

\ \\\\\\\\\\\\\\ Exported Interface:
\ *
\ Generic device methods:
\ *


\ \\\\\\\\\\\\\\ Exported Interface:
\ *
\ *

false VALUE esc-on
false VALUE csi-on
defer esc-process
0 VALUE esc-num-parm
0 VALUE esc-num-parm2
0 VALUE saved-line#
0 VALUE saved-column#

: get-esc-parm ( default -- value )
	esc-num-parm dup 0> IF nip ELSE drop THEN 0 to esc-num-parm ;
: get-esc-parm2 ( default -- value )
	esc-num-parm2 dup 0> IF nip ELSE drop THEN 0 to esc-num-parm2 ;
: set-esc-parm ( newdigit -- ) [char] 0 - esc-num-parm a * + to esc-num-parm ;

: reverse-cursor ( oldpos -- newpos) dup IF 1 get-esc-parm - THEN ;
: advance-cursor ( bound oldpos -- newpos) tuck > IF 1 get-esc-parm + THEN ;
: erase-in-line #columns column# - dup 0> IF delete-characters ELSE drop THEN ;

: terminal-line++ ( -- )
	line# 1+ dup #lines = IF 1- 0 to line# 1 delete-lines THEN
	to line#
;

0 VALUE dang
0 VALUE blipp
false VALUE stopcsi
0 VALUE term-background
7 VALUE term-foreground

: set-term-color
   dup d# 30 d# 39 between IF dup d# 30 - to term-foreground THEN
   dup d# 40 d# 49 between IF dup d# 40 - to term-background THEN
   0 = IF
      0 to term-background
      7 to term-foreground
  THEN
  term-foreground term-background <= to inverse?
;

: ansi-esc ( char -- )
    csi-on IF
	dup [char] 0 [char] 9 between IF set-esc-parm
	ELSE true to stopcsi CASE
	    [char] A OF line# reverse-cursor to line# ENDOF
	    [char] B OF #lines line# advance-cursor to line# ENDOF
	    [char] C OF #columns column# advance-cursor to column# ENDOF
	    [char] D OF column# reverse-cursor to column# ENDOF
	    [char] E OF ( FIXME: Cursor Next Line - No idea what does it mean )
	    	#lines line# advance-cursor to line#
	    ENDOF
	    [char] f OF
		1 get-esc-parm2 to line# column# get-esc-parm to column#
	    ENDOF
	    [char] H OF
		1 get-esc-parm2 to line# column# get-esc-parm to column#
	    ENDOF
	    ( second parameter delimiter for f and H commands )
	    [char] ; OF false to stopcsi 0 get-esc-parm to esc-num-parm2 ENDOF
	    [char] ? OF false to stopcsi ENDOF ( FIXME: Ignore that for now )
	    [char] l OF ENDOF ( FIXME: ?25l should hide cursor )
	    [char] h OF ENDOF ( FIXME: ?25h should show cursor )
	    [char] J OF
		#lines line# - dup 0> IF
			line# 1+ to line# delete-lines line# 1- to line#
		ELSE drop THEN
		erase-in-line
	    ENDOF
	    [char] K OF erase-in-line ENDOF
	    [char] L OF 1 get-esc-parm insert-lines ENDOF
	    [char] M OF 1 get-esc-parm delete-lines ENDOF
	    [char] @ OF 1 get-esc-parm insert-characters ENDOF
	    [char] P OF 1 get-esc-parm delete-characters ENDOF
	    [char] m OF 0 get-esc-parm set-term-color ENDOF
	    ( These are non-ANSI commands recommended by OpenBoot )
	    [char] p OF inverse-screen? IF false to inverse-screen?
			inverse? 0= to inverse? invert-screen
		THEN
	    ENDOF
	    [char] q OF inverse-screen? 0= IF true to inverse-screen?
			inverse? 0= to inverse? invert-screen
		THEN
	    ENDOF
\ 	    [char] s OF reset-screen ENDOF ( FIXME: this conflicts w. ANSI )
\ 	    [char] s OF line# to saved-line# column# to saved-column# ENDOF
	    [char] u OF saved-line# to line# saved-column# to column# ENDOF
	    dup dup to dang OF blink-screen ENDOF
	ENDCASE stopcsi IF false to csi-on
	        false to esc-on 0 to esc-num-parm 0 to esc-num-parm2 THEN
	THEN
    ELSE CASE
	( DEV VT compatibility stuff used by accept.fs )
	[char] 7 OF line# to saved-line# column# to saved-column# ENDOF
	[char] 8 OF saved-line# to line# saved-column# to column# ENDOF
	[char] [ OF true to csi-on ENDOF
	dup dup OF false to esc-on to blipp ENDOF
        ENDCASE
	csi-on 0= IF false to esc-on THEN 0 to esc-num-parm 0 to esc-num-parm2
    THEN
;

' ansi-esc to esc-process
CREATE twtracebuf 4000 allot twtracebuf 4000 erase
twtracebuf VALUE twbp
0 VALUE twbc
0 VALUE twtrace-enabled?

: twtrace
	twbc 4000 = IF 0 to twbc twtracebuf to twbp THEN
	dup twbp c! twbp 1+ to twbp twbc 1+ to twbc
;

: terminal-write ( addr len -- actual-len )
 	cursor-off
	tuck bounds ?DO i c@
		twtrace-enabled? IF twtrace THEN
		esc-on IF esc-process
		ELSE CASE
			1B OF true to esc-on ENDOF
			carret OF 0 to column# ENDOF
			linefeed OF terminal-line++ ENDOF
			bell OF blink-screen ENDOF
			9 ( TAB ) OF column# 7 + -8 and dup #columns < IF
					to column#
				ELSE drop THEN
			ENDOF
			B ( VT ) OF line# ?dup IF 1- to line# THEN ENDOF
			C ( FF ) OF 0 to line# 0 to column# erase-screen ENDOF
			bs OF	column# 1- dup 0< IF
					line# IF
						line# 1- to line#
						drop #columns 1-
					ELSE drop column#
					THEN
				THEN
				to column# ( bl draw-character )
			ENDOF
			dup OF
				i c@ draw-character
				column# 1+ dup #columns >= IF
					drop 0 terminal-line++
				THEN
				to column#
			ENDOF
		    ENDCASE
		THEN
	LOOP
 	restore-cursor
;
