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


s" fat-files" device-name

INSTANCE VARIABLE bytes/sector
INSTANCE VARIABLE sectors/cluster
INSTANCE VARIABLE #reserved-sectors
INSTANCE VARIABLE #fats
INSTANCE VARIABLE #root-entries
INSTANCE VARIABLE total-#sectors
INSTANCE VARIABLE media-descriptor
INSTANCE VARIABLE sectors/fat
INSTANCE VARIABLE sectors/track
INSTANCE VARIABLE #heads
INSTANCE VARIABLE #hidden-sectors

INSTANCE VARIABLE fat-type
INSTANCE VARIABLE bytes/cluster
INSTANCE VARIABLE fat-offset
INSTANCE VARIABLE root-offset
INSTANCE VARIABLE cluster-offset
INSTANCE VARIABLE #clusters

: seek  s" seek" $call-parent ;
: read  s" read" $call-parent ;

INSTANCE VARIABLE data
INSTANCE VARIABLE #data

: free-data
  data @ ?dup IF #data @ free-mem  0 data ! THEN ;
: read-data ( offset size -- )
  free-data  dup #data ! alloc-mem data !
  xlsplit seek            -2 and ABORT" fat-files read-data: seek failed"
  data @ #data @ read #data @ <> ABORT" fat-files read-data: read failed" ;

CREATE fat-buf 8 allot
: read-fat ( cluster# -- data )
  fat-buf 8 erase
  1 #split fat-type @ * 2/ 2/ fat-offset @ +
  xlsplit seek -2 and ABORT" fat-files read-fat: seek failed"
  fat-buf 8 read 8 <> ABORT" fat-files read-fat: read failed"
  fat-buf 8c@ bxjoin fat-type @ dup >r 2* #split drop r> #split
  rot IF swap THEN drop ;
  
INSTANCE VARIABLE next-cluster

: read-cluster ( cluster# -- )
  dup bytes/cluster @ * cluster-offset @ + bytes/cluster @ read-data
  read-fat dup #clusters @ >= IF drop 0 THEN next-cluster ! ;
: read-dir ( cluster# -- )
  ?dup 0= IF root-offset @ #root-entries @ 20 * read-data 0 next-cluster !
  ELSE read-cluster THEN ;

: .time ( x -- )
  base @ >r decimal
  b #split 2 0.r [char] : emit  5 #split 2 0.r [char] : emit  2* 2 0.r
  r> base ! ;
: .date ( x -- )
  base @ >r decimal
  9 #split 7bc + 4 0.r [char] - emit  5 #split 2 0.r [char] - emit  2 0.r
  r> base ! ;
: .attr ( attr -- )
  6 0 DO dup 1 and IF s" RHSLDA" drop i + c@ ELSE bl THEN emit u2/ LOOP drop ;
: .dir-entry ( adr -- )
  dup 0b + c@ 8 and IF drop EXIT THEN \ volume label, not a file
  dup c@ e5 = IF drop EXIT THEN \ deleted file
  cr
  dup 1a + 2c@ bwjoin [char] # emit 4 0.r space \ starting cluster
  dup 18 + 2c@ bwjoin .date space
  dup 16 + 2c@ bwjoin .time space
  dup 1c + 4c@ bljoin base @ decimal swap a .r base ! space \ size in bytes
  dup 0b + c@ .attr space
  dup 8 BEGIN 2dup 1- + c@ 20 = over and WHILE 1- REPEAT type
  dup 8 + 3 BEGIN 2dup 1- + c@ 20 = over and WHILE 1- REPEAT dup IF
  [char] . emit type ELSE 2drop THEN
  drop ;
: .dir-entries ( adr n -- )
  0 ?DO dup i 20 * + dup c@ 0= IF drop LEAVE THEN .dir-entry LOOP drop ;
: .dir ( cluster# -- )
  read-dir BEGIN data @ #data @ 20 / .dir-entries next-cluster @ WHILE
  next-cluster @ read-cluster REPEAT ;

: str-upper ( str len adr -- ) \ Copy string to adr, uppercase
  -rot bounds ?DO i c@ upc over c! char+ LOOP drop ;
CREATE dos-name b allot
: make-dos-name ( str len -- )
  dos-name b bl fill
  2dup [char] . findchar IF
  3dup 1+ /string 3 min dos-name 8 + str-upper nip THEN
  8 min dos-name str-upper ;

: (find-file) ( -- cluster file-len is-dir? true | false )
  data @ BEGIN dup data @ #data @ + < WHILE
  dup dos-name b comp WHILE 20 + REPEAT
  dup 1a + 2c@ bwjoin swap dup 1c + 4c@ bljoin swap 0b + c@ 10 and 0<> true
  ELSE drop false THEN ;
: find-file ( dir-cluster name len -- cluster file-len is-dir? true | false )
  make-dos-name read-dir BEGIN (find-file) 0= WHILE next-cluster @ WHILE
  next-cluster @ read-cluster REPEAT false ELSE true THEN ;
: find-path ( dir-cluster name len -- cluster file-len true | false )
  dup 0= IF 3drop false ."  empty name " EXIT THEN
  over c@ [char] \ = IF 1 /string  RECURSE EXIT THEN
  [char] \ split 2>r find-file 0= IF 2r> 2drop false ."  not found " EXIT THEN
  r@ 0<> <> IF 2drop 2r> 2drop false ."  no dir<->file match " EXIT THEN
  r@ 0<> IF drop 2r> RECURSE EXIT THEN
  2r> 2drop true ;
  
: do-super ( -- )
  0 200 read-data
  data @ 0b + 2c@ bwjoin bytes/sector !
  data @ 0d + c@ sectors/cluster !
  bytes/sector @ sectors/cluster @ * bytes/cluster !
  data @ 0e + 2c@ bwjoin #reserved-sectors !
  data @ 10 + c@ #fats !
  data @ 11 + 2c@ bwjoin #root-entries !
  data @ 13 + 2c@ bwjoin total-#sectors !
  data @ 15 + c@ media-descriptor !
  data @ 16 + 2c@ bwjoin sectors/fat !
  data @ 18 + 2c@ bwjoin sectors/track !
  data @ 1a + 2c@ bwjoin #heads !
  data @ 1c + 2c@ bwjoin #hidden-sectors !

  \ For FAT16 and FAT32:
  total-#sectors @ 0= IF data @ 20 + 4c@ bljoin total-#sectors ! THEN

  \ For FAT32:
  sectors/fat @ 0= IF data @ 24 + 4c@ bljoin sectors/fat ! THEN

  \ XXX add other FAT32 stuff (offsets 28, 2c, 30)

  \ Compute the number of data clusters, decide what FAT type we are.
  total-#sectors @ #reserved-sectors @ - sectors/fat @ #fats @ * -
  #root-entries @ 20 * bytes/sector @ // - sectors/cluster @ /
  dup #clusters !
  dup ff5 < IF drop c ELSE fff5 < IF 10 ELSE 20 THEN THEN fat-type !
  base @ decimal base !

  \ Starting offset of first fat.
  #reserved-sectors @ bytes/sector @ * fat-offset !

  \ Starting offset of root dir.
  #fats @ sectors/fat @ * bytes/sector @ * fat-offset @ + root-offset !

  \ Starting offset of "cluster 0".
  #root-entries @ 20 * bytes/sector @ tuck // * root-offset @ +
  bytes/cluster @ 2* - cluster-offset ! ;


INSTANCE VARIABLE file-cluster
INSTANCE VARIABLE file-len
INSTANCE VARIABLE current-pos
INSTANCE VARIABLE pos-in-data

: seek ( lo hi -- status )
  lxjoin dup current-pos ! file-cluster @ read-cluster
  \ Read and skip blocks until we are where we want to be.
  BEGIN dup #data @ >= WHILE #data @ - next-cluster @ dup 0= IF
  2drop true EXIT THEN read-cluster REPEAT pos-in-data ! false ;
: read ( adr len -- actual )
  file-len @ current-pos @ - min \ can't go past end of file
  #data @ pos-in-data @ - min >r \ length for this transfer
  data @ pos-in-data @ + swap r@ move \ move the data
  r@ pos-in-data +!  r@ current-pos +!  pos-in-data @ #data @ = IF
  next-cluster @ ?dup IF read-cluster 0 pos-in-data ! THEN THEN r> ;
: read ( adr len -- actual )
  file-len @ min                \ len cannot be greater than file size
  dup >r BEGIN dup WHILE 2dup read dup 0= ABORT" fat-files: read failed"
  /string ( tuck - >r + r> ) REPEAT 2drop r> ;
: load ( adr -- len )
  file-len @ read dup file-len @ <> ABORT" fat-files: failed loading file" ;

: close  free-data ;
: open
  do-super
  0 my-args find-path 0= IF close false EXIT THEN
  file-len !  file-cluster !  0 0 seek 0= ;
