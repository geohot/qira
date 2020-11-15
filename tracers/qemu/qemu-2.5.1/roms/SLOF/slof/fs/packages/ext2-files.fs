\ *****************************************************************************
\ * Copyright (c) 2004, 2011 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/
s" ext2-files" device-name

INSTANCE VARIABLE first-block
INSTANCE VARIABLE inode-size
INSTANCE VARIABLE block-size
INSTANCE VARIABLE inodes/group

INSTANCE VARIABLE group-desc-size
INSTANCE VARIABLE group-descriptors

: seek  s" seek" $call-parent ;
: read  s" read" $call-parent ;

INSTANCE VARIABLE data
INSTANCE VARIABLE #data
INSTANCE VARIABLE indirect-block
INSTANCE VARIABLE dindirect-block

: free-data
  data @ ?dup IF #data @ free-mem  0 data ! THEN ;
: read-data ( offset size -- )
  free-data  dup #data ! alloc-mem data !
  xlsplit seek            -2 and ABORT" ext2-files read-data: seek failed"
  data @ #data @ read #data @ <> ABORT" ext2-files read-data: read failed" ;

: read-block ( block# -- )
  block-size @ * block-size @ read-data ;

INSTANCE VARIABLE inode
INSTANCE VARIABLE file-len
INSTANCE VARIABLE blocks
INSTANCE VARIABLE #blocks
INSTANCE VARIABLE ^blocks
INSTANCE VARIABLE #blocks-left
: blocks-read ( n -- )  dup negate #blocks-left +! 4 * ^blocks +! ;
: read-indirect-blocks ( indirect-block# -- )
  read-block data @ data off
  dup #blocks-left @ 4 * block-size @ min dup >r ^blocks @ swap move
  r> 2 rshift blocks-read block-size @ free-mem ;

: read-double-indirect-blocks ( double-indirect-block# -- )
   \ Resolve one level of indirection and call read-indirect-block
   read-block data @ indirect-block ! data off
   BEGIN
      indirect-block @ l@-le dup 0 <>
   WHILE
      read-indirect-blocks
      4 indirect-block +!       \ point to next indirect block
   REPEAT
   drop                         \ drop 0, the invalid block number
;

: read-triple-indirect-blocks ( triple-indirect-block# -- )
   \ Resolve one level of indirection and call double-indirect-block
   read-block data @ dindirect-block ! data off
   BEGIN
      dindirect-block @ l@-le dup 0 <>
   WHILE
      read-double-indirect-blocks
      4 dindirect-block +!      \ point to next double indirect block
   REPEAT
   drop                         \ drop 0, the invalid block number
;

: read-block#s ( -- )
  blocks @ ?dup IF #blocks @ 4 * free-mem THEN
  inode @ 4 + l@-le file-len !
  file-len @ block-size @ // #blocks !
  #blocks @ 4 * alloc-mem blocks !
  blocks @ ^blocks !  #blocks @ #blocks-left !
  #blocks-left @ c min \ # direct blocks
  inode @ 28 + over 4 * ^blocks @ swap move blocks-read
  #blocks-left @ IF inode @ 58 + l@-le read-indirect-blocks THEN
  #blocks-left @ IF inode @ 5c + l@-le read-double-indirect-blocks THEN
  #blocks-left @ IF inode @ 60 + l@-le read-triple-indirect-blocks THEN ;
: read-inode ( inode# -- )
  1- inodes/group @ u/mod \ # in group, group #
  20 * group-descriptors @ + 8 + l@-le block-size @ * \ # in group, inode table
  swap inode-size @ * + xlsplit seek drop  inode @ inode-size @ read drop
;

: .rwx ( bits last-char-if-special special? -- )
  rot dup 4 and IF ." r" ELSE ." -" THEN
      dup 2 and IF ." w" ELSE ." -" THEN
  swap IF 1 and 0= IF upc THEN emit ELSE
          1 and IF ." x" ELSE ." -" THEN drop THEN ;
CREATE mode-chars 10 allot s" ?pc?d?b?-?l?s???" mode-chars swap move
: .mode ( mode -- )
  dup c rshift f and mode-chars + c@ emit
  dup 6 rshift 7 and over 800 and 73 swap .rwx
  dup 3 rshift 7 and over 400 and 73 swap .rwx
  dup          7 and swap 200 and 74 swap .rwx ;
: .inode ( -- )
  base @ >r decimal
  inode @      w@-le .mode \ file mode
  inode @ 1a + w@-le 5 .r \ link count
  inode @ 02 + w@-le 9 .r \ uid
  inode @ 18 + w@-le 9 .r \ gid
  inode @ 04 + l@-le 9 .r \ size
  r> base ! ;

: do-super ( -- )
  400 400 read-data
  data @ 14 + l@-le first-block !
  400 data @ 18 + l@-le lshift block-size !
  data @ 28 + l@-le inodes/group !
  \ Check revision level... in revision 0, the inode size is always 128
  data @ 4c + l@-le 0= IF
     80 inode-size !
  ELSE
     data @ 58 + w@-le inode-size !
  THEN
  data @ 20 + l@-le group-desc-size !

  \ Read the group descriptor table:
  first-block @ 1+ block-size @ *
  group-desc-size @
  read-data
  data @ group-descriptors !

  \ We keep the group-descriptor memory area, so clear data pointer:
  data off
;

INSTANCE VARIABLE current-pos

: read ( adr len -- actual )
  file-len @ current-pos @ - min \ can't go past end of file
  current-pos @ block-size @ u/mod 4 * blocks @ + l@-le read-block
  block-size @ over - rot min >r ( adr off r: len )
  data @ + swap r@ move r> dup current-pos +! ;
: read ( adr len -- actual )
  ( check if a file is selected, first )
  dup >r BEGIN dup WHILE 2dup read dup 0= ABORT" ext2-files: read failed"
  /string REPEAT 2drop r> ;
: seek ( lo hi -- status )
  lxjoin dup file-len @ > IF drop true EXIT THEN current-pos ! false ;
: load ( adr -- len )
  file-len @ read dup file-len @ <> ABORT" ext2-files: failed loading file" ;

: .name ( adr -- )  dup 8 + swap 6 + c@ type ;
: read-dir ( inode# -- adr )
  read-inode read-block#s file-len @ alloc-mem
  0 0 seek ABORT" ext2-files read-dir: seek failed"
  dup file-len @ read file-len @ <> ABORT" ext2-files read-dir: read failed" ;
: .dir ( inode# -- )
  read-dir dup BEGIN 2dup file-len @ - > over l@-le tuck and WHILE
  cr dup 8 0.r space read-inode .inode space space dup .name
  dup 4 + w@-le + REPEAT 2drop file-len @ free-mem ;
: (find-file) ( adr name len -- inode#|0 )
  2>r dup BEGIN 2dup file-len @ - > over l@-le and WHILE
  dup 8 + over 6 + c@ 2r@ str= IF 2r> 2drop nip l@-le EXIT THEN
  dup 4 + w@-le + REPEAT 2drop 2r> 2drop 0 ;
: find-file ( inode# name len -- inode#|0 )
  2>r read-dir dup 2r> (find-file) swap file-len @ free-mem ;
: find-path ( inode# name len -- inode#|0 )
  dup 0= IF 3drop 0 ."  empty name " EXIT THEN
  over c@ [char] \ = IF 1 /string ."  slash " RECURSE EXIT THEN
  [char] \ split 2>r find-file ?dup 0= IF
  2r> 2drop false ."  not found " EXIT THEN
  r@ 0<> IF 2r> ."  more... " RECURSE EXIT THEN
  2r> 2drop ."  got it " ;

: close
   inode @ inode-size @ free-mem
   group-descriptors @ group-desc-size @ free-mem
   free-data
   blocks @ ?dup IF #blocks @ 4 * free-mem THEN
;

: open
  0 data ! 0 blocks ! 0 #blocks !
  do-super
  inode-size @ alloc-mem inode !
  my-args nip 0= IF 0 0 ELSE
  2 my-args find-path ?dup 0= IF close false EXIT THEN THEN
  read-inode read-block#s 0 0 seek 0= ;
