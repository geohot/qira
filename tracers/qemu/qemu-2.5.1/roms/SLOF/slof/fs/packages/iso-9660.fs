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


s" iso-9660" device-name


0 VALUE iso-debug-flag

\ Method for code clean up - For release version of code iso-debug-flag is
\ cleared  and for debugging it is set

: iso-debug-print ( str len -- )  iso-debug-flag IF type cr ELSE 2drop THEN  ;


\ --------------------------------------------------------
\ GLOBAL  VARIABLES
\ --------------------------------------------------------


0 VALUE  path-tbl-size
0 VALUE  path-tbl-addr
0 VALUE  root-dir-size
0 VALUE  vol-size
0 VALUE  logical-blk-size
0 VALUE  path-table
0 VALUE  count


\ INSTANCE VARIABLES


INSTANCE VARIABLE dir-addr
INSTANCE VARIABLE data-buff
INSTANCE VARIABLE #data
INSTANCE VARIABLE ptable
INSTANCE VARIABLE file-loc
INSTANCE VARIABLE file-size
INSTANCE VARIABLE cur-file-offset
INSTANCE VARIABLE self
INSTANCE VARIABLE index


\ --------------------------------------------------------
\ COLON DEFINITIONS
\ --------------------------------------------------------


\ This method is used to seek to the required position
\ Which calls seek of disk-label

: seek  ( pos.lo pos.hi -- status )  s" seek" $call-parent  ;


\ This method is used to read the contents of disk
\ it calls read of disk-label


 : read  ( addr len -- actual )  s" read" $call-parent  ;


\ This method releases the memory used as  scratch pad buffer.

: free-data ( -- )
   data-buff @                              ( data-buff )
   ?DUP  IF  #data @  free-mem  0 data-buff ! 0 #data ! THEN
;


\ This method will release the previous allocated scratch pad buffer and
\ allocates a fresh buffer and copies the required number of bytes from the
\ media in to it.

: read-data ( offset size -- )
   dup #data @ > IF
      free-data dup dup                  ( offset size size size )
      #data ! alloc-mem data-buff !      ( offset size )
   THEN
   swap xlsplit                          ( size pos.lo pos.hi )
   seek   -2 and ABORT" seek failed."
   data-buff @ over read                 ( size actual )
   <> ABORT" read failed."
;


\ This method extracts the information required from primary volume
\ descriptor and stores the required information in the global variables

: extract-vol-info  (  --  )
   10  800 * 800 read-data
   data-buff @  88  + l@-be  to path-tbl-size   \ read path table size
   data-buff @  94  + l@-be  to path-tbl-addr   \ read big-endian  path table
   data-buff @  a2  + l@-be   dir-addr !        \ gather of root directory info
   data-buff @  0aa + l@-be  to root-dir-size   \ get volume info
   data-buff @  54  + l@-be  to vol-size        \ size in blocks
   data-buff @  82  + l@-be  to logical-blk-size
   path-tbl-size alloc-mem dup  TO path-table path-tbl-size erase
   path-tbl-addr 800 *  xlsplit seek  drop
   path-table  path-tbl-size  read  drop     \ pathtable in-system-memory copy
;


\ This method coverts the iso file name to user readble form

: file-name  ( str len --  str' len' )
   2dup  [char] ; findchar  IF
      ( str len offset )
      nip                 \ Omit the trailing ";1" revision of ISO9660 file name
      2dup + 1-           ( str newlen endptr )
      c@ [CHAR] . = IF
         1-               ( str len' )    \ Remove trailing dot
      THEN
   THEN
;


\ triplicates top stack element

: dup3  ( num  -- num num num ) dup dup dup  ;


\ This method is used for traversing records of path table. If the
\ file identifier length is odd 1 byte padding is done else not.

: get-next-record  ( rec-addr -- next-rec-offset )
   dup3               ( rec-addr rec-addr rec-addr rec-addr )
   self @ 1 +  self ! ( rec-addr rec-addr rec-addr rec-addr )
   c@  1 AND  IF      ( rec-addr rec-addr rec-addr )
      c@ +  9         ( rec-addr rec-addr' rec-len )
   ELSE
      c@ +  8         ( rec-addr rec-addr' rec-len )
   THEN
   + swap  -          ( next-rec-offset )
;


\  This method does search of given directory name in the path table
\ and returns true  if finds a match else  false.

: path-table-search ( str len -- TRUE | FALSE )
   path-table path-tbl-size +  path-table ptable @ +  DO ( str len )
      2dup  I 6 + w@-be index @ =                        ( str len str len )
      -rot  I 8 +  I c@
      iso-debug-flag IF
          ." ISO: comparing path name '"
          4dup type ." ' with '" type ." '" cr
      THEN
      string=ci and  IF                                  ( str len )
         s" Directory Matched!!  "   iso-debug-print     ( str len )
         self @   index !                                ( str len )
         I 2 + l@-be   dir-addr ! I  dup                 ( str len rec-addr )
         get-next-record + path-table -   ptable !       ( str len )
         2drop  TRUE UNLOOP EXIT                         ( TRUE )
      THEN
      I get-next-record                           ( str len next-rec-offset )
   +LOOP
   2drop
   FALSE                                          ( FALSE )
   s" Invalid path / directory "  iso-debug-print
;


\ METHOD for searching for a file with in a direcotory

: search-file-dir ( str len  -- TRUE | FALSE )
   dir-addr @  800 *  dir-addr !             ( str len )
   dir-addr @ 100 read-data                  ( str len )
   data-buff @  0e + l@-be  dup >r           ( str len rec-len )
   100 >  IF                                 ( str len )
      s" size dir record"  iso-debug-print   ( str len )
      dir-addr @ r@  read-data               ( str len )
   THEN
   r> data-buff @  + data-buff @  DO         ( str len )
      I 19 + c@  2 and 0=  I c@ 0<> and IF   ( str len )
         2dup                                ( str len  str len )
         I 21 + I 20 + c@                    ( str len  str len  str' len' )
         iso-debug-flag IF
             ." ISO: comparing file name '"
             4dup type ." ' with '" type ." '" cr
         THEN
         file-name  string=ci  IF            ( str len )
            s" File found!"  iso-debug-print ( str len )
            I 6 + l@-be 800 *                ( str len file-loc )
            file-loc !                       ( str len )
            I 0e + l@-be  file-size !        ( str len )
            2drop
            TRUE                             ( TRUE )
            UNLOOP
            EXIT
         THEN
      THEN
      ( str len )
      I c@ ?dup 0= IF
         800 I 7ff AND -
         iso-debug-flag IF
            ." skipping " dup . ." bytes at end of sector" cr
         THEN
      THEN
      ( str len offset )
   +LOOP
   2drop
   FALSE                                     ( FALSE )
   s" file not found"   iso-debug-print
;


\ This method splits the given absolute path in to directories from root and
\ calls search-path-table. when string reaches to state when it can not be
\ split i.e., end of the path, calls search-file-dir is made to search for
\ file .

: search-path ( str len -- FALSE|TRUE )
   0  ptable !
   1  self !
   1  index !
   dup                                             ( str len len )
   0=  IF
      3drop FALSE                                  ( FALSE )
      s"  Empty path name "  iso-debug-print  EXIT ( FALSE )
   THEN
   OVER c@                                         ( str len char )
   [char] \ =  IF                                  ( str len )
      swap 1 + swap 1 -  BEGIN                     ( str len )
         [char] \  split                           ( str len  str' len ' )
         dup 0 =   IF                              ( str len  str' len ' )
            2drop search-file-dir EXIT             ( TRUE | FALSE )
         ELSE
            2swap path-table-search  invert  IF    ( str' len ' )
               2drop FALSE  EXIT                   ( FALSE )
            THEN
         THEN
      AGAIN
   ELSE   BEGIN
      [char] \  split   dup 0 =   IF               ( str len str' len' )
         2drop search-file-dir EXIT                ( TRUE | FALSE )
      ELSE
         2swap path-table-search  invert  IF       ( str' len ' )
            2drop FALSE  EXIT                      ( FALSE )
            THEN
         THEN
      AGAIN
   THEN
;


\ this method will seek and read the file in to the given memory location

0 VALUE loc
: load ( addr -- len )
   dup to loc                     ( addr )
   file-loc @  xlsplit seek drop
   file-size @  read              ( file-size )
   iso-debug-flag IF s" Bytes returned from read:" type dup . cr THEN
   dup file-size @  <> ABORT" read failed!"
;



\ memory used by the file system will be freed

: close ( -- )
   free-data   count 1 - dup to count  0 =  IF
      path-table path-tbl-size free-mem
      0 TO path-table
   THEN
;


\ open method of the file system

: open ( -- TRUE | FALSE )
   0 data-buff !
   0 #data !
   0 ptable !
   0 file-loc !
   0 file-size !
   0 cur-file-offset !
   1 self !
   1 index !
   count 0 =  IF
      s" extract-vol-info called "   iso-debug-print
      extract-vol-info
   THEN
   count  1 + to count
   my-args search-path  IF
      file-loc @  xlsplit seek drop
      TRUE    ( TRUE )
   ELSE
      close
      FALSE   ( FALSE )
   THEN
   0 cur-file-offset !
   s" opened ISO9660 package" iso-debug-print
;


\ public seek method

: seek ( pos.lo pos.hi -- status )
   lxjoin dup  cur-file-offset !  ( offset )
   file-loc @  + xlsplit          ( pos.lo pos.hi )
   s" seek" $call-parent          ( status )
;


\ public read method

 : read ( addr len -- actual )
    file-size @ cur-file-offset @ -             ( addr len remainder-of-file )
    min                                         ( addr len|remainder-of-file )
    s" read" $call-parent                       ( actual )
    dup cur-file-offset @ +  cur-file-offset !  ( actual )
    cur-file-offset @                           ( offset actual )
    xlsplit seek drop                           ( actual )
;

