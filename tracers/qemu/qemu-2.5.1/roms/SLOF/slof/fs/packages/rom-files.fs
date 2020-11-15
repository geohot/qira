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


\ package which adds support to read the romfs
\ this package is somehow limited as the maximum supported length
\ for a file name is hardcoded to 0x100

s" rom-files" device-name

INSTANCE VARIABLE length
INSTANCE VARIABLE next-file
INSTANCE VARIABLE buffer
INSTANCE VARIABLE buffer-size
INSTANCE VARIABLE file
INSTANCE VARIABLE file-size
INSTANCE VARIABLE found

: open  true 
  100 dup buffer-size ! alloc-mem buffer ! false found ! ;
: close buffer @ buffer-size @ free-mem ;

: read ( addr len -- actual ) s" read" $call-parent ;

: seek ( lo hi -- status ) s" seek" $call-parent ;

: .read-file-name ( offset -- str len )
  \ move to the file name offset
  0 seek drop 
  \ read <buffer-size> bytes from that address
  buffer @ buffer-size @ read drop
  \ write a 0 to make sure it is a 0 terminated string
  buffer-size @ 1 - buffer @ + 0 swap c!
  buffer @ zcount ;

: .print-info ( offset -- )
  dup 2 spaces 6 0.r 2 spaces dup
  8 + 0 seek drop length 8 read drop
  6 length @ swap 0.r 2 spaces
  20 + .read-file-name type cr ;

: .list-header cr
  s" --offset---size-----file-name----" type cr ;

: list
  .list-header
  0 0 BEGIN + dup 
  .print-info dup 0 seek drop
  next-file 8 read drop next-file @
  dup 0= UNTIL 2drop ;

: (find-file)  ( name len -- offset | -1 )
   0 0 seek drop false found !
   file-size ! file ! 0 0 BEGIN + dup
   20 + .read-file-name file @ file-size @
   str= IF true found ! THEN
   dup 0 seek drop
   next-file 8 read drop next-file @
   dup 0= found @ or UNTIL drop found @ 0=
   IF drop -1 THEN ;

: load  ( addr -- size )
   my-parent instance>args 2@ [char] \ left-parse-string 2drop
   (find-file) dup -1 = IF 2drop 0 ELSE
      \ got to the beginning
      0 0 seek drop
      \ read the file size
      dup 8 + 0 seek drop
      here 8 read drop here @  ( dest-addr offset file-size )
      \ read data start offset
      over 18 + 0 seek drop
      here 8 read drop here @  ( dest-addr offset file-size data-offset )
      rot + 0 seek drop  ( dest-addr file-size )
      read 
   THEN
;
