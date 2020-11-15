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


\ Set debug-disk-label? to true to get debug messages for the disk-label code.
false VALUE debug-disk-label?

\ This value defines the maximum number of blocks (512b) to load from a PREP
\ partition. This is required to keep the load time in reasonable limits if the
\ PREP partition becomes big.
\ If we ever want to put a large kernel with initramfs from a PREP partition
\ we might need to increase this value. The default value is 65536 blocks (32MB)
d# 65536 value max-prep-partition-blocks
d# 4096 CONSTANT block-array-size

s" disk-label" device-name

0 INSTANCE VALUE partition
0 INSTANCE VALUE part-offset
0 INSTANCE VALUE disk-chrp-boot

0 INSTANCE VALUE part-start
0 INSTANCE VALUE lpart-start
0 INSTANCE VALUE part-size
0 INSTANCE VALUE dos-logical-partitions

0 INSTANCE VALUE block-size
0 INSTANCE VALUE block

0 INSTANCE VALUE args
0 INSTANCE VALUE args-len

0 INSTANCE VALUE gpt-part-size
0 INSTANCE VALUE seek-pos


INSTANCE VARIABLE block#  \ variable to store logical sector#
INSTANCE VARIABLE hit#    \ partition counter
INSTANCE VARIABLE success-flag

\ ISO9660 specific information
0ff constant END-OF-DESC
3 constant  PARTITION-ID
48 constant VOL-PART-LOC


\ DOS partition label (MBR) specific structures

STRUCT
       1b8 field mbr>boot-loader
        /l field mbr>disk-signature
        /w field mbr>null
        40 field mbr>partition-table
        /w field mbr>magic

CONSTANT /mbr

STRUCT
        /c field part-entry>active
        /c field part-entry>start-head
        /c field part-entry>start-sect
        /c field part-entry>start-cyl
        /c field part-entry>id
        /c field part-entry>end-head
        /c field part-entry>end-sect
        /c field part-entry>end-cyl
        /l field part-entry>sector-offset
        /l field part-entry>sector-count

CONSTANT /partition-entry

STRUCT
        8 field gpt>signature
        4 field gpt>revision
        4 field gpt>header-size
        4 field gpt>header-crc32
        4 field gpt>reserved
        8 field gpt>current-lba
        8 field gpt>backup-lba
        8 field gpt>first-lba
        8 field gpt>last-lba
       10 field gpt>disk-guid
        8 field gpt>part-entry-lba
        4 field gpt>num-part-entry
        4 field gpt>part-entry-size
        4 field gpt>part-array-crc32
      1a4 field gpt>reserved

CONSTANT /gpt-header

STRUCT
       10 field gpt-part-entry>part-type-guid
       10 field gpt-part-entry>part-guid
        8 field gpt-part-entry>first-lba
        8 field gpt-part-entry>last-lba
        8 field gpt-part-entry>attribute
       48 field gpt-part-entry>part-name

CONSTANT /gpt-part-entry

\ Defined by IEEE 1275-1994 (3.8.1)

: offset ( d.rel -- d.abs )
   part-offset xlsplit d+
;

: seek  ( pos.lo pos.hi -- status )
   offset
   debug-disk-label? IF 2dup ." seek-parent: pos.hi=0x" u. ." pos.lo=0x" u. THEN
   s" seek" $call-parent
   debug-disk-label? IF dup ." status=" . cr THEN
;

: read ( addr len -- actual )
   debug-disk-label? IF 2dup swap ." read-parent: addr=0x" u. ." len=" .d THEN
   s" read" $call-parent
   debug-disk-label? IF dup ." actual=" .d cr THEN
;


\ read sector to array "block"
: read-sector ( sector-number -- )
   \ block-size is 0x200 on disks, 0x800 on cdrom drives
   block-size * 0 seek drop      \ seek to sector
   block block-size read drop    \ read sector
;

: (.part-entry) ( part-entry )
   cr ." part-entry>active:        " dup part-entry>active c@ .d
   cr ." part-entry>start-head:    " dup part-entry>start-head c@ .d
   cr ." part-entry>start-sect:    " dup part-entry>start-sect c@ .d
   cr ." part-entry>start-cyl:     " dup part-entry>start-cyl  c@ .d
   cr ." part-entry>id:            " dup part-entry>id c@ .d
   cr ." part-entry>end-head:      " dup part-entry>end-head c@ .d
   cr ." part-entry>end-sect:      " dup part-entry>end-sect c@ .d
   cr ." part-entry>end-cyl:       " dup part-entry>end-cyl c@ .d
   cr ." part-entry>sector-offset: " dup part-entry>sector-offset l@-le .d
   cr ." part-entry>sector-count:  " dup part-entry>sector-count l@-le .d
   cr
;

: (.name) r@ begin cell - dup @ <colon> = UNTIL xt>name cr type space ;

: init-block ( -- )
   s" block-size" ['] $call-parent CATCH IF ABORT" parent has no block-size." THEN
   to block-size
   block-array-size alloc-mem
   dup block-array-size erase
   to block
   debug-disk-label? IF
      ." init-block: block-size=" block-size .d ." block=0x" block u. cr
   THEN
;

: partition>part-entry ( partition -- part-entry )
   1- /partition-entry * block mbr>partition-table +
;

: partition>start-sector ( partition -- sector-offset )
   partition>part-entry part-entry>sector-offset l@-le
;

\ This word returns true if the currently loaded block has _NO_ MBR magic
: no-mbr? ( -- true|false )
   0 read-sector
   1 partition>part-entry part-entry>id c@ ee = IF TRUE EXIT THEN \ GPT partition found
   block mbr>magic w@-le aa55 <>
;

\ This word returns true if the currently loaded block has _NO_ GPT partition id
: no-gpt? ( -- true|false )
   0 read-sector
   1 partition>part-entry part-entry>id c@ ee <> IF true EXIT THEN
   block mbr>magic w@-le aa55 <>
;

: pc-extended-partition? ( part-entry-addr -- true|false )
   part-entry>id c@      ( id )
   dup 5 = swap          ( true|false id )
   dup f = swap          ( true|false true|false id )
   85 =                  ( true|false true|false true|false )
   or or                 ( true|false )
;

: count-dos-logical-partitions ( -- #logical-partitions )
   no-mbr? IF 0 EXIT THEN
   0 5 1 DO                                ( current )
      i partition>part-entry               ( current part-entry )
      dup pc-extended-partition? IF
         part-entry>sector-offset l@-le    ( current sector )
         dup to part-start to lpart-start  ( current )
         BEGIN
            part-start read-sector          \ read EBR
            1 partition>start-sector IF
               \ ." Logical Partition found at " part-start .d cr
               1+
            THEN \ another logical partition
            2 partition>start-sector
            ( current relative-sector )
            ?dup IF lpart-start + to part-start false ELSE true THEN
         UNTIL
      ELSE
         drop
      THEN
   LOOP
;

: (get-dos-partition-params) ( ext-part-start part-entry -- offset count active? id )
   dup part-entry>sector-offset l@-le rot + swap ( offset part-entry )
   dup part-entry>sector-count l@-le swap        ( offset count part-entry )
   dup part-entry>active c@ 80 = swap            ( offset count active? part-entry )
   part-entry>id c@                              ( offset count active? id )
;

: find-dos-partition ( partition# -- false | offset count active? id true )
   to partition 0 to part-start 0 to part-offset

   \ no negative partitions
   partition 0<= IF 0 to partition false EXIT THEN

   \ load MBR and check it
   no-mbr? IF 0 to partition false EXIT THEN

   partition 4 <= IF \ Is this a primary partition?
      0 partition partition>part-entry
      (get-dos-partition-params)
      \ FIXME sanity checks?
      true EXIT
   ELSE
      partition 4 - 0 5 1 DO                      ( logical-partition current )
         i partition>part-entry                   ( log-part current part-entry )
         dup pc-extended-partition? IF
            part-entry>sector-offset l@-le        ( log-part current sector )
            dup to part-start to lpart-start      ( log-part current )
            BEGIN
               part-start read-sector             \ read EBR
               1 partition>start-sector IF        \ first partition entry
                  1+ 2dup = IF                    ( log-part current )
                     2drop
                     part-start 1 partition>part-entry
                     (get-dos-partition-params)
                     true UNLOOP EXIT
                  THEN
                  2 partition>start-sector
                  ( log-part current relative-sector )

                  ?dup IF lpart-start + to part-start false ELSE true THEN
               ELSE
                  true
               THEN
            UNTIL
         ELSE
            drop
         THEN
      LOOP
      2drop false
   THEN
;

: try-dos-partition ( -- okay? )
   \ Read partition table and check magic.
   no-mbr? IF
       debug-disk-label? IF cr ." No DOS disk-label found." cr THEN
       false EXIT
   THEN

   count-dos-logical-partitions TO dos-logical-partitions

   debug-disk-label? IF
      ." Found " dos-logical-partitions .d ." logical partitions" cr
      ." Partition = " partition .d cr
   THEN

   partition 1 5 dos-logical-partitions +
   within 0= IF
      cr ." Partition # not 1-" 4 dos-logical-partitions + . cr false EXIT
   THEN

   \ Could/should check for valid partition here...  the magic is not enough really.

   \ Get the partition offset.

   partition find-dos-partition IF
     ( offset count active? id )
     2drop
     to part-size
     block-size * to part-offset
     true
   ELSE
     false
   THEN
;

\ Check for an ISO-9660 filesystem on the disk
\ : try-iso9660-partition ( -- true|false )
\ implement me if you can ;-)
\ ;


\ Check for an ISO-9660 filesystem on the disk
\ (cf. CHRP IEEE 1275 spec., chapter 11.1.2.3)
: has-iso9660-filesystem  ( -- TRUE|FALSE )
   \ Seek to the beginning of logical 2048-byte sector 16
   \ refer to Chapter C.11.1 in PAPR 2.0 Spec
   \ was: 10 read-sector, but this might cause trouble if you
   \ try booting an ISO image from a device with 512b sectors.
   10 800 * 0 seek drop      \ seek to sector
   block 800 read drop       \ read sector
   \ Check for CD-ROM volume magic:
   block c@ 1 =
   block 1+ 5 s" CD001"  str=
   and
   dup IF 800 to block-size THEN
;


\ Load from first active DOS boot partition.

: fat-bootblock? ( addr -- flag )
   \ byte 0-2 of the bootblock is a jump instruction in
   \ all FAT filesystems.
   \ e9 and eb are jump instructions in x86 assembler.
   dup c@ e9 = IF drop true EXIT THEN
   dup c@ eb = swap 2+ c@ 90 = and
;

\ NOTE: block-size is always 512 bytes for DOS partition tables.

: load-from-dos-boot-partition ( addr -- size )
   no-mbr? IF drop FALSE EXIT THEN  \ read MBR and check for DOS disk-label magic

   count-dos-logical-partitions TO dos-logical-partitions

   debug-disk-label? IF
      ." Found " dos-logical-partitions .d ." logical partitions" cr
      ." Partition = " partition .d cr
   THEN

   \ Now walk through the partitions:
   5 dos-logical-partitions + 1 DO
      \ ." checking partition " i .
      i find-dos-partition IF        ( addr offset count active? id )
         41 = and                    ( addr offset count prep-boot-part? )
         IF                          ( addr offset count )
            max-prep-partition-blocks min  \ reduce load size
            swap                     ( addr count offset )
            block-size * to part-offset
            0 0 seek drop            ( addr offset )
            block-size * read        ( size )
            UNLOOP EXIT
         ELSE
            2drop                    ( addr )
         THEN
      THEN
   LOOP
   drop 0
;

\ Check for GPT PReP partition GUID. Only first 3 blocks are
\ byte-swapped treating last two blocks as contigous for simplifying
\ comparison
9E1A2D38            CONSTANT GPT-PREP-PARTITION-1
C612                CONSTANT GPT-PREP-PARTITION-2
4316                CONSTANT GPT-PREP-PARTITION-3
AA268B49521E5A8B    CONSTANT GPT-PREP-PARTITION-4

: gpt-prep-partition? ( -- true|false )
   block gpt-part-entry>part-type-guid
   dup l@-le     GPT-PREP-PARTITION-1 <> IF drop false EXIT THEN
   dup 4 + w@-le GPT-PREP-PARTITION-2 <> IF drop false EXIT THEN
   dup 6 + w@-le GPT-PREP-PARTITION-3 <> IF drop false EXIT THEN
       8 + x@    GPT-PREP-PARTITION-4 =
;

\ Check for GPT MSFT BASIC DATA GUID - fat based
EBD0A0A2            CONSTANT GPT-BASIC-DATA-PARTITION-1
B9E5                CONSTANT GPT-BASIC-DATA-PARTITION-2
4433                CONSTANT GPT-BASIC-DATA-PARTITION-3
87C068B6B72699C7    CONSTANT GPT-BASIC-DATA-PARTITION-4

: gpt-basic-data-partition? ( -- true|false )
   block gpt-part-entry>part-type-guid
   dup l@-le     GPT-BASIC-DATA-PARTITION-1 <> IF drop false EXIT THEN
   dup 4 + w@-le GPT-BASIC-DATA-PARTITION-2 <> IF drop false EXIT THEN
   dup 6 + w@-le GPT-BASIC-DATA-PARTITION-3 <> IF drop false EXIT THEN
       8 + x@    GPT-BASIC-DATA-PARTITION-4 =
;

\
\ GPT Signature
\ ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h)
\
4546492050415254 CONSTANT GPT-SIGNATURE

\ The routine checks whether the protective MBR has GPT ID and then
\ reads the gpt data from the sector. Also set the seek position and
\ the partition size used in caller routines.

: get-gpt-partition ( -- true|false )
   no-gpt? IF false EXIT THEN
   debug-disk-label? IF cr ." GPT partition found " cr  THEN
   1 read-sector
   block gpt>part-entry-lba x@-le
   block-size * to seek-pos
   block gpt>part-entry-size l@-le to gpt-part-size
   gpt-part-size block-array-size > IF
      cr ." GPT part size exceeds buffer allocated " cr
      false exit
   THEN
   block gpt>signature x@ GPT-SIGNATURE =
;

: load-from-gpt-prep-partition ( addr -- size )
   get-gpt-partition 0= IF false EXIT THEN
   block gpt>num-part-entry l@-le dup 0= IF false exit THEN
   1+ 1 ?DO
      seek-pos 0 seek drop
      block gpt-part-size read drop gpt-prep-partition? IF
         debug-disk-label? IF  ." GPT PReP partition found " cr THEN
         block gpt-part-entry>first-lba x@-le ( addr first-lba )
         block gpt-part-entry>last-lba x@-le  ( addr first-lba last-lba)
         over - 1+                            ( addr first-lba blocks )
         swap                                 ( addr blocks first-lba )
         block-size * to part-offset          ( addr blocks )
         0 0 seek drop                        ( addr blocks )
         block-size * read                    ( size )
         UNLOOP EXIT
     THEN
     seek-pos gpt-part-size + to seek-pos
   LOOP
   false
;

: try-gpt-dos-partition ( -- true|false )
   get-gpt-partition 0= IF false EXIT THEN
   block gpt>num-part-entry l@-le dup 0= IF false EXIT THEN
   1+ 1 ?DO
      seek-pos 0 seek drop
      block gpt-part-size read drop
      gpt-basic-data-partition? IF
         debug-disk-label? IF ." GPT BASIC DATA partition found " cr THEN
         block gpt-part-entry>first-lba x@-le       ( first-lba )
         dup to part-start                          ( first-lba )
         block gpt-part-entry>last-lba x@-le        ( first-lba last-lba )
         over - 1+                                  ( first-lba s1 )
         block-size * to part-size                  ( first-lba )
         block-size * to part-offset                ( )
         0 0 seek drop
         block block-size read drop
         block fat-bootblock?                    ( true|false )
         UNLOOP EXIT
      THEN
      seek-pos gpt-part-size + to seek-pos
   LOOP
   false
;

\ Extract the boot loader path from a bootinfo.txt file
\ In: address and length of buffer where the bootinfo.txt has been loaded to.
\ Out: string address and length of the boot loader (within the input buffer)
\      or a string with length = 0 when parsing failed.

\ Here is a sample bootinfo file:
\ <chrp-boot>
\   <description>Linux Distribution</description>
\   <os-name>Linux</os-name>
\   <boot-script>boot &device;:1,\boot\yaboot.ibm</boot-script>
\   <icon size=64,64 color-space=3,3,2>
\     <bitmap>[..]</bitmap>
\   </icon>
\ </chrp-boot>

: parse-bootinfo-txt  ( addr len -- str len )
   2dup s" <boot-script>" find-substr       ( addr len pos1 )
   2dup = IF
      \ String not found
      3drop 0 0 EXIT
   THEN
   dup >r - swap r> + swap                  ( addr1 len1 )

   2dup s" &device;:" find-substr           ( addr1 len1 posdev )
   2dup = IF
      3drop 0 0 EXIT
   THEN
   9 +                                      \ Skip the "&device;:" string
   dup >r - swap r> + swap                  ( addr2 len2 )
   2dup s" </boot-script>" find-substr nip  ( addr2 len3 )

   debug-disk-label? IF
      ." Extracted boot loader from bootinfo.txt: '"
      2dup type ." '" cr
   THEN
;

\ Try to load \ppc\bootinfo.txt from the disk (used mainly on CD-ROMs), and if
\ available, get the boot loader path from this file and load it.
\ See the "CHRP system binding to IEEE 1275" specification for more information
\ about bootinfo.txt. An example file can be found in the comment of
\ parse-bootinfo-txt ( addr len -- str len )

: load-chrp-boot-file ( addr -- size )
   \ Create bootinfo.txt path name and load that file:
   my-parent instance>path
   disk-chrp-boot @ 1 = IF
       s" :1,\ppc\bootinfo.txt" $cat strdup       ( addr str len )
   ELSE
       s" :\ppc\bootinfo.txt" $cat strdup       ( addr str len )
   THEN
   open-dev dup 0= IF 2drop 0 EXIT THEN
   >r dup                                   ( addr addr R:ihandle )
   dup s" load" r@ $call-method             ( addr addr size R:ihandle )
   r> close-dev                             ( addr addr size )

   \ Now parse the information from bootinfo.txt:
   parse-bootinfo-txt                       ( addr fnstr fnlen )
   dup 0= IF 3drop 0 EXIT THEN
   \ Does the string contain parameters (i.e. a white space)?
   2dup 20 findchar IF
      ( addr fnstr fnlen offset )
      >r 2dup r@ - 1- swap r@ + 1+ swap     ( addr fnstr fnlen pstr plen  R: offset )
      encode-string s" bootargs" set-chosen
      drop r>
   THEN

   \ Create the full path to the boot loader:
   my-parent instance>path      ( addr fnstr fnlen nstr nlen )
   s" :" $cat 2swap $cat strdup             ( addr str len )
   \ Update the bootpath:
   2dup encode-string s" bootpath" set-chosen
   \ And finally load the boot loader itself:
   open-dev dup 0= IF ." failed to load CHRP boot loader." 2drop 0 EXIT THEN
   >r s" load" r@ $call-method              ( size R:ihandle )
   r> close-dev                             ( size )
;

\ load from a bootable partition
: load-from-boot-partition ( addr -- size )
   debug-disk-label? IF ." Trying DOS boot " .s cr THEN
   dup load-from-dos-boot-partition ?dup 0 <> IF nip EXIT THEN

   debug-disk-label? IF ." Trying CHRP boot " .s cr THEN
   1 disk-chrp-boot !
   dup load-chrp-boot-file ?dup 0 <> IF nip EXIT THEN
   0 disk-chrp-boot !

   debug-disk-label? IF ." Trying GPT boot " .s cr THEN
   load-from-gpt-prep-partition
   \ More boot partition formats ...
;

\ parse partition number from my-args

\ my-args has the following format
\ [<partition>[,<path>]]

\ | example my-args  | example boot command      |
\ +------------------+---------------------------+
\ | 1,\boot\vmlinuz  | boot disk:1,\boot\vmlinuz |
\ | 2                | boot disk:2               |

\ 0 means the whole disk, this is the same behavior
\ as if no partition is specified (yaboot wants this).

: parse-partition ( -- okay? )
   0 to partition
   0 to part-offset
   0 to part-size

   my-args to args-len to args

   debug-disk-label? IF
      cr ." disk-label parse-partition: my-args=" my-args type cr
   THEN

   \ Called without arguments?
   args-len 0 = IF true EXIT THEN

   \ Check for "full disk" arguments.
   my-args [char] , findchar 0= IF \ no comma?
      args c@ isdigit not IF       \ ... and not a partition number?
         true EXIT                 \ ... then it's not a partition we can parse
      THEN
   ELSE
      drop
   THEN
   my-args [char] , split to args-len to args
   dup 0= IF 2drop true EXIT THEN \ no first argument

   \ Check partition #.
   base @ >r decimal $number r> base !
   IF cr ." Not a partition #" false EXIT THEN

   \ Store part #, done.
   to partition
   true
;


\ try-files and try-partitions

: (interpose-filesystem) ( str len -- )
   find-package IF args args-len rot interpose THEN
;

: try-dos-files ( -- found? )
   no-mbr? IF false EXIT THEN

   block fat-bootblock? 0= IF false EXIT THEN
   s" fat-files" (interpose-filesystem)
   true
;

: try-ext2-files ( -- found? )
   2 read-sector               \ read first superblock
   block d# 56 + w@-le         \ fetch s_magic
   ef53 <> IF false EXIT THEN  \ s_magic found?
   s" ext2-files" (interpose-filesystem)
   true
;


: try-iso9660-files
   has-iso9660-filesystem 0= IF false exit THEN
   s" iso-9660" (interpose-filesystem)
   true
;

: try-files ( -- found? )
   \ If no path, then full disk.
   args-len 0= IF true EXIT THEN

   try-dos-files IF true EXIT THEN
   try-ext2-files IF true EXIT THEN
   try-iso9660-files IF true EXIT THEN

   \ ... more filesystem types here ...

   false
;

: try-partitions ( -- found? )
   try-dos-partition IF try-files EXIT THEN
   try-gpt-dos-partition IF try-files EXIT THEN
   \ try-iso9660-partition IF try-files EXIT THEN
   \ ... more partition types here...
   false
;

\ Interface functions for disk-label package
\ as defined by IEEE 1275-1994 3.8.1

: close ( -- )
   debug-disk-label? IF ." Closing disk-label: block=0x" block u. ." block-size=" block-size .d cr THEN
   block block-array-size free-mem
;


: open ( -- true|false )
   init-block

   parse-partition 0= IF
      close
      false EXIT
   THEN

   partition IF
       try-partitions
   ELSE
       try-files
   THEN
   dup 0= IF debug-disk-label? IF ." not found." cr THEN close THEN \ free memory again
;


\ Boot & Load w/o arguments is assumed to be boot from boot partition

: load ( addr -- size )
   debug-disk-label? IF
      ." load: " dup u. cr
   THEN

   args-len IF
      TRUE ABORT" Load done w/o filesystem"
   ELSE
      partition IF
         0 0 seek drop
         part-size IF
            part-size max-prep-partition-blocks min   \ Load size
         ELSE
            max-prep-partition-blocks
         THEN
         200 *  read
      ELSE
         has-iso9660-filesystem IF
             dup load-chrp-boot-file ?dup 0 > IF nip EXIT THEN
         THEN
         load-from-boot-partition
	 dup 0= ABORT" No boot partition found"
      THEN
   THEN
;
