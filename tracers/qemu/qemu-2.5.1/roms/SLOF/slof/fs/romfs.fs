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

STRUCT
	cell field romfs>file-header
	cell field romfs>data
	cell field romfs>data-size
	cell field romfs>flags

CONSTANT /romfs-lookup-control-block

CREATE romfs-lookup-cb /romfs-lookup-control-block allot
romfs-lookup-cb /romfs-lookup-control-block erase

: create-filename ( string -- string\0 )
    here >r dup 8 + allot
    r@ over 8 + erase
    r@ zplace r> ;

: romfs-lookup ( fn-str fn-len -- data size | false )
    create-filename romfs-base
    romfs-lookup-cb romfs-lookup-entry call-c
    0= IF romfs-lookup-cb dup romfs>data @ swap romfs>data-size @ ELSE
    false THEN ;

: ibm,romfs-lookup ( fn-str fn-len -- data-high data-low size | 0 0 false )
  romfs-lookup dup
  0= if drop 0 0 false else
  swap dup 20 rshift swap ffffffff and then ;

\ FIXME For a short time ...
: romfs-lookup-client ibm,romfs-lookup ;

\ Fixme temp implementation

STRUCT
	cell field romfs>next-off
	cell field romfs>size
	cell field romfs>flags
	cell field romfs>data-off
	cell field romfs>name

CONSTANT /romfs-cb

: romfs-map-file ( fn-str fn-len -- file-addr file-size )
  romfs-base >r
  BEGIN 2dup r@ romfs>name zcount string=ci not WHILE
    ( fn-str fn-len ) ( R: rom-cb-file-addr )
    r> romfs>next-off dup @ dup 0= IF 1 THROW THEN + >r REPEAT
    ( fn-str fn-len ) ( R: rom-cb-file-addr )
    2drop r@ romfs>data-off @ r@ + r> romfs>size @ ;

\ returns address of romfs-header file
: flash-header ( -- address | false )
    get-flash-base 28 +         \ prepare flash header file address
    dup rx@                     \ fetch "magic123"
    6d61676963313233 <> IF      \ IF flash is not valid
       drop                     \ | forget address
       false                    \ | return false
    THEN                        \ FI
;

CREATE bdate-str 10 allot
: bdate2human ( -- addr len )
  flash-header 40 + rx@ (.)
  drop dup 0 + bdate-str 6 + 4 move
  dup 4 + bdate-str 0 + 2 move
  dup 6 + bdate-str 3 + 2 move
  dup 8 + bdate-str b + 2 move
  a + bdate-str e + 2 move
  2d bdate-str 2 + c!
  2d bdate-str 5 + c!
  20 bdate-str a + c!
  3a bdate-str d + c!
  bdate-str 10
;


\ Look up a file in the ROM file system and evaluate it

: included  ( fn fn-len -- )
   2dup >r >r romfs-lookup dup IF
      r> drop r> drop evaluate
   ELSE
      drop ." Cannot open file : " r> r> type cr
   THEN
;

: include  ( " fn " -- )
   parse-word included
;

: ?include  ( flag " fn " -- )
   parse-word rot IF included ELSE 2drop THEN
;

: include?  ( nargs flag " fn " -- )
   parse-word rot IF
      rot drop included
   ELSE
      2drop 0 ?DO drop LOOP
   THEN
;


\ List files in ROMfs

: (print-romfs-file-info)  ( file-addr -- )
   9 emit  dup b 0.r  2 spaces  dup 8 + @ 6 0.r  2 spaces  20 + zcount type cr
;

: romfs-list  ( -- )
   romfs-base 0 cr BEGIN + dup (print-romfs-file-info) dup @ dup 0= UNTIL 2drop
;
