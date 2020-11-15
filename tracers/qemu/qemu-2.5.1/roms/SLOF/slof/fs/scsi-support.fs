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

\ ************************************************
\ create a new scsi word-list named 'scsi-words'
\ ************************************************
vocabulary scsi-words                  \ create new word list named 'scsi-words'
also scsi-words  definitions           \ place next definitions into new list

\ for some commands specific parameters are used, which normally
\ need not to be altered. These values are preset at include time
\ or explicit by a call of 'scsi-supp-init'
false  value   scsi-param-debug        \ common debugging flag
d# 0   value   scsi-param-size         \ length of CDB processed last
h# 0   value   scsi-param-control      \ control word for CDBs as defined in SAM-4
d# 0   value   scsi-param-errors       \ counter for detected errors

\ utility to increment error counter
: scsi-inc-errors
   scsi-param-errors 1 + to scsi-param-errors
;

\ ***************************************************************************
\ SCSI-Command: TEST UNIT READY
\         Type: Primary Command (SPC-3 clause 6.33)
\ ***************************************************************************
\ Forth Word:   scsi-build-test-unit-ready    ( cdb -- )
\ ***************************************************************************
\ checks if a device is ready to receive commands
\ ***************************************************************************
\ command code:
00 CONSTANT scsi-cmd-test-unit-ready
\ CDB structure:
STRUCT
	/c	FIELD test-unit-ready>operation-code     \ 00h
	4	FIELD test-unit-ready>reserved           \ unused
	/c	FIELD test-unit-ready>control            \ control byte as specified in SAM-4
CONSTANT scsi-length-test-unit-ready

\ cdb build:
\ all fields are zeroed
: scsi-build-test-unit-ready  ( cdb -- )
   dup scsi-length-test-unit-ready erase  ( cdb )
   scsi-param-control swap test-unit-ready>control c!  ( )
   scsi-length-test-unit-ready to scsi-param-size   \ update CDB length
;

\ ***************************************************************************
\ SCSI-Command: REPORT LUNS
\         Type: Primary Command
\ ***************************************************************************
\ Forth Word:   scsi-build-report-luns    ( cdb -- )
\ ***************************************************************************
\ report all LUNs supported by a device
\ ***************************************************************************
\ command code:
a0 CONSTANT scsi-cmd-report-luns
\ CDB structure:
STRUCT
	/c	FIELD report-luns>operation-code     \ a0h
	1	FIELD report-luns>reserved           \ unused
        /c      FIELD report-luns>select-report      \ report select byte
        3       FIELD report-luns>reserved2          \ unused
        /l      FIELD report-luns>alloc-length       \ report length
	1	FIELD report-luns>reserved3          \ unused
	/c	FIELD report-luns>control            \ control byte
CONSTANT scsi-length-report-luns

\ cdb build:
\ all fields are zeroed
: scsi-build-report-luns ( alloc-len cdb -- )
   dup scsi-length-report-luns erase              \ 12 bytes CDB
	scsi-cmd-report-luns over	          ( alloc-len cdb cmd cdb )
	report-luns>operation-code c!	          ( alloc-len cdb )
   scsi-param-control over report-luns>control c! ( alloc-len cdb )
	report-luns>alloc-length l!	  \ size of Data-In Buffer
   scsi-length-report-luns to scsi-param-size     \ update CDB length
;

\ ***************************************************************************
\ SCSI-Command: REQUEST SENSE
\         Type: Primary Command (SPC-3 clause 6.27)
\ ***************************************************************************
\ Forth Word:   scsi-build-request-sense    ( cdb -- )
\ ***************************************************************************
\ for return data a buffer of at least 252 bytes must be present!
\ see spec: SPC-3 (r23) / clauses 4.5 and 6.27
\ ***************************************************************************
\ command code:
03 CONSTANT scsi-cmd-request-sense
\ CDB structure:
STRUCT
	/c	FIELD request-sense>operation-code     \ 03h
	3	FIELD request-sense>reserved           \ unused
	/c	FIELD request-sense>allocation-length  \ buffer-length for data response
	/c	FIELD request-sense>control            \ control byte as specified in SAM-4
CONSTANT scsi-length-request-sense

\ cdb build:
: scsi-build-request-sense    ( alloc-len cdb -- )
   >r                         ( alloc-len )  ( R: -- cdb )
   r@ scsi-length-request-sense erase  ( alloc-len )
   scsi-cmd-request-sense r@           ( alloc-len cmd cdb )
   request-sense>operation-code c!     ( alloc-len )
   dup d# 252 >                        \ buffer length too big ?
   IF
      scsi-inc-errors
      drop d# 252                      \ replace with 252
   ELSE
      dup d# 18 <                      \ allocated buffer too small ?
      IF
         scsi-inc-errors
         drop 0                        \ reject return data
      THEN
   THEN                                      ( alloclen )
   r@ request-sense>allocation-length c!     (  )
   scsi-param-control r> request-sense>control c!  ( alloc-len cdb )  ( R: cdb -- )
   scsi-length-request-sense to scsi-param-size  \ update CDB length
;

\ ----------------------------------------
\ SCSI-Response: SENSE_DATA
\ ----------------------------------------
70 CONSTANT scsi-response(request-sense-0)
71 CONSTANT scsi-response(request-sense-1)

STRUCT
   /c FIELD sense-data>response-code   \ 70h (current errors) or 71h (deferred errors)
   /c FIELD sense-data>obsolete
   /c FIELD sense-data>sense-key       \ D3..D0 = sense key, D7 = EndOfMedium
   /l FIELD sense-data>info
   /c FIELD sense-data>alloc-length    \ <= 244 (for max size)
   /l FIELD sense-data>command-info
   /c FIELD sense-data>asc             \ additional sense key
   /c FIELD sense-data>ascq            \ additional sense key qualifier
   /c FIELD sense-data>unit-code
   3  FIELD sense-data>key-specific
   /c FIELD sense-data>add-sense-bytes \ start of appended extra bytes
CONSTANT scsi-length-sense-data

\ ----------------------------------------
\ get from SCSI response block:
\  - Additional Sense Code Qualifier
\  - Additional Sense Code
\  - sense-key
\ ----------------------------------------
\ Forth Word:   scsi-get-sense-data  ( addr -- ascq asc sense-key )
\ ----------------------------------------
: scsi-get-sense-data                  ( addr -- ascq asc sense-key )   
   >r                                  ( R: -- addr )
   r@ sense-data>response-code c@ 7f and 72 >= IF
     r@ 3 + c@                           ( ascq )
     r@ 2 + c@                           ( ascq asc ) 
     r> 1 + c@ 0f and                    ( ascq asc sense-key )
   ELSE
     r@ sense-data>ASCQ c@               ( ascq )
     r@ sense-data>ASC c@                ( ascq asc )
     r> sense-data>sense-key c@ 0f and   ( ascq asc sense-key ) ( R: addr -- )
   THEN
;

\ --------------------------------------------------------------------------
\ Forth Word:   scsi-get-sense-data?  ( addr -- false | ascq asc sense-key true )
\ --------------------------------------------------------------------------
: scsi-get-sense-data?                 ( addr -- false | ascq asc sense-key true )
   dup
   sense-data>response-code c@
   7e AND dup 70 = swap 72 = or         \ Response code (some devices have MSB set)
   IF
      scsi-get-sense-data TRUE
   ELSE
      drop FALSE        \ drop addr
   THEN

;

\ --------------------------------------------------------------------------
\ Forth Word:   scsi-get-sense-ID?  ( addr -- false | sense-ID true )
\ same as scsi-get-sense-data? but returns
\ a single word composed of: sense-key<<16 | asc<<8 | ascq
\ --------------------------------------------------------------------------
: scsi-get-sense-ID?                 ( addr -- false | ascq asc sense-key true )
   dup
   sense-data>response-code c@
   7e AND 70 =          \ Response code (some devices have MSB set)
   IF
      scsi-get-sense-data        ( ascq asc sense-key )
      10 lshift                  ( ascq asc sense-key16 )
      swap 8 lshift or           ( ascq sense-key+asc )
      swap or                    \ 24-bit sense-ID ( sense-key+asc+ascq )
      TRUE
   ELSE
      drop FALSE        \ drop addr
   THEN
;

\ ***************************************************************************
\ SCSI-Command: INQUIRY
\         Type: Primary Command (SPC-3 clause 6.4)
\ ***************************************************************************
\ Forth Word:   scsi-build-inquiry    ( alloc-len cdb -- )
\ ***************************************************************************
\ command code:
12 CONSTANT scsi-cmd-inquiry

\ CDB structure
STRUCT
	/c	FIELD inquiry>operation-code     \ 0x12
	/c	FIELD inquiry>reserved           \ + EVPD-Bit (vital product data)
	/c	FIELD inquiry>page-code          \ page code for vital product data (if used)
	/w	FIELD inquiry>allocation-length  \ length of Data-In-Buffer
	/c	FIELD inquiry>control            \ control byte as specified in SAM-4
CONSTANT scsi-length-inquiry

\ Setup command INQUIRY
: scsi-build-inquiry                   ( alloc-len cdb -- )
   dup scsi-length-inquiry erase       \ 6 bytes CDB
	scsi-cmd-inquiry over				   ( alloc-len cdb cmd cdb )
	inquiry>operation-code c!	         ( alloc-len cdb )
   scsi-param-control over inquiry>control c! ( alloc-len cdb )
	inquiry>allocation-length w!	      \ size of Data-In Buffer
   scsi-length-inquiry to scsi-param-size    \ update CDB length
;

\ ----------------------------------------
\ block structure of inquiry return data:
\ ----------------------------------------
STRUCT
	/c	   FIELD inquiry-data>peripheral       \ qualifier and device type
	/c	   FIELD inquiry-data>reserved1
	/c	   FIELD inquiry-data>version          \ supported SCSI version (1,2,3)
	/c	   FIELD inquiry-data>data-format
	/c	   FIELD inquiry-data>add-length       \ total block length - 4
	/c	   FIELD inquiry-data>flags1
	/c	   FIELD inquiry-data>flags2
	/c	   FIELD inquiry-data>flags3
	d# 8	FIELD inquiry-data>vendor-ident     \ vendor string
	d# 16	FIELD inquiry-data>product-ident    \ device string
	/l 	FIELD inquiry-data>product-revision \ revision string
	d# 20	FIELD inquiry-data>vendor-specific  \ optional params
\ can be increased by vendor specific fields
CONSTANT scsi-length-inquiry-data

\ ***************************************************************************
\ SCSI-Command: READ CAPACITY (10)
\         Type: Block Command (SBC-3 clause 5.12)
\ ***************************************************************************
\ Forth Word:   scsi-build-read-capacity-10    ( cdb -- )
\ ***************************************************************************
25 CONSTANT scsi-cmd-read-capacity-10  \ command code

STRUCT                                 \ SCSI 10-byte CDB structure
	/c	FIELD read-cap-10>operation-code
	/c	FIELD read-cap-10>reserved1
	/l	FIELD read-cap-10>lba
	/w	FIELD read-cap-10>reserved2
	/c	FIELD read-cap-10>reserved3
	/c	FIELD read-cap-10>control
CONSTANT scsi-length-read-cap-10

\ Setup READ CAPACITY (10) command
: scsi-build-read-cap-10                     ( cdb -- )
   dup scsi-length-read-cap-10 erase         ( cdb )
	scsi-cmd-read-capacity-10 over            ( cdb cmd cdb )
	read-cap-10>operation-code c!             ( cdb )
   scsi-param-control swap read-cap-10>control c! ( )
   scsi-length-read-cap-10 to scsi-param-size    \ update CDB length
;

\ ----------------------------------------
\ get from SCSI response block:
\  - Additional Sense Code Qualifier
\  - Additional Sense Code
\  - sense-key
\ ----------------------------------------
\ Forth Word:   scsi-get-capacity-10  ( addr -- block-size #blocks )
\ ----------------------------------------
\ Block structure
STRUCT
	/l	FIELD read-cap-10-data>max-lba
	/l	FIELD read-cap-10-data>block-size
CONSTANT scsi-length-read-cap-10-data

\ get data-block
: scsi-get-capacity-10                 ( addr -- block-size #blocks )
   >r                                  ( addr -- ) ( R: -- addr )
   r@ read-cap-10-data>block-size l@   ( block-size )
   r> read-cap-10-data>max-lba l@      ( block-size #blocks ) ( R: addr -- )
;

\ ***************************************************************************
\ SCSI-Command: READ CAPACITY (16)
\         Type: Block Command (SBC-3 clause 5.13)
\ ***************************************************************************
\ Forth Word:   scsi-build-read-capacity-16    ( cdb -- )
\ ***************************************************************************
9e CONSTANT scsi-cmd-read-capacity-16        \ command code

STRUCT                                       \ SCSI 16-byte CDB structure
	/c	FIELD read-cap-16>operation-code
	/c	FIELD read-cap-16>service-action
	/l	FIELD read-cap-16>lba-high
	/l	FIELD read-cap-16>lba-low
	/l	FIELD read-cap-16>allocation-length    \ should be 32
	/c	FIELD read-cap-16>reserved
	/c	FIELD read-cap-16>control
CONSTANT scsi-length-read-cap-16

\ Setup READ CAPACITY (16) command
: scsi-build-read-cap-16  ( cdb -- )
   >r r@                                     ( R: -- cdb )
   scsi-length-read-cap-16 erase             (  )
	scsi-cmd-read-capacity-16                 ( code )
	r@ read-cap-16>operation-code c!          (  )
   10 r@ read-cap-16>service-action c!
   d# 32                                     \ response size 32 bytes
   r@ read-cap-16>allocation-length l!       (  )
   scsi-param-control r> read-cap-16>control c! ( R: cdb -- )
   scsi-length-read-cap-16 to scsi-param-size \ update CDB length
;

\ ----------------------------------------
\ get from SCSI response block:
\  - Block Size (in Bytes)
\  - Number of Blocks
\ ----------------------------------------
\ Forth Word:   scsi-get-capacity-16  ( addr -- block-size #blocks )
\ ----------------------------------------
\ Block structure for return data
STRUCT
	/l	FIELD read-cap-16-data>max-lba-high    \ upper quadlet of Max-LBA
	/l	FIELD read-cap-16-data>max-lba-low     \ lower quadlet of Max-LBA
	/l	FIELD read-cap-16-data>block-size      \ logical block length in bytes
   /c	FIELD read-cap-16-data>protect         \ type of protection (4 bits)
   /c	FIELD read-cap-16-data>exponent        \ logical blocks per physical blocks
   /w	FIELD read-cap-16-data>lowest-aligned  \ first LBA of a phsy. block
   10 FIELD read-cap-16-data>reserved        \ 16 reserved bytes
CONSTANT scsi-length-read-cap-16-data        \ results in 32

\ get data-block
: scsi-get-capacity-16                       ( addr -- block-size #blocks )
   >r                                        ( R: -- addr )
   r@ read-cap-16-data>block-size l@         ( block-size )
   r@ read-cap-16-data>max-lba-high l@       ( block-size #blocks-high )
   d# 32 lshift                              ( block-size #blocks-upper )
   r> read-cap-16-data>max-lba-low l@ +      ( block-size #blocks ) ( R: addr -- )
;

\ ***************************************************************************
\ SCSI-Command: MODE SENSE (10)
\         Type: Primary Command (SPC-3 clause 6.10)
\ ***************************************************************************
\ Forth Word:   scsi-build-mode-sense-10  ( alloc-len subpage page cdb -- )
\ ***************************************************************************
5a CONSTANT scsi-cmd-mode-sense-10

\ CDB structure
STRUCT
	/c	FIELD mode-sense-10>operation-code
	/c	FIELD mode-sense-10>res-llbaa-dbd-res
	/c	FIELD mode-sense-10>pc-page-code       \ page code + page control
	/c	FIELD mode-sense-10>sub-page-code
	3	FIELD mode-sense-10>reserved2
	/w	FIELD mode-sense-10>allocation-length
	/c	FIELD mode-sense-10>control
CONSTANT scsi-length-mode-sense-10

: scsi-build-mode-sense-10                   ( alloc-len subpage page cdb -- )
   >r                                        ( alloc-len subpage page ) ( R: -- cdb )
   r@ scsi-length-mode-sense-10 erase        \ 10 bytes CDB
	scsi-cmd-mode-sense-10                    ( alloc-len subpage page cmd )
   r@  mode-sense-10>operation-code c!		   ( alloc-len subpage page )
   10 r@ mode-sense-10>res-llbaa-dbd-res c!  \ long LBAs accepted
	r@ mode-sense-10>pc-page-code c!	         ( alloc-len subpage )
	r@ mode-sense-10>sub-page-code c!	      ( alloc-len )
	r@ mode-sense-10>allocation-length w!     ( )

   scsi-param-control r> mode-sense-10>control c!  ( R: cdb -- )
   scsi-length-mode-sense-10 to scsi-param-size  \ update CDB length
;

\ return data processing
\ (see spec: SPC-3 clause 7.4.3)

STRUCT
	/w	FIELD mode-sense-10-data>head-length
	/c	FIELD mode-sense-10-data>head-medium
	/c	FIELD mode-sense-10-data>head-param
	/c	FIELD mode-sense-10-data>head-longlba
	/c	FIELD mode-sense-10-data>head-reserved
	/w	FIELD mode-sense-10-data>head-descr-len
CONSTANT scsi-length-mode-sense-10-data

\ ****************************************
\ This function shows the mode page header
\ helpful for further analysis
\ ****************************************
: .mode-sense-data   ( addr -- )
   cr
   dup mode-sense-10-data>head-length
   w@ ." Mode Length: " .d space
   dup mode-sense-10-data>head-medium
   c@ ." / Medium Type: " .d space
   dup mode-sense-10-data>head-longlba
   c@ ." / Long LBA: " .d space
   mode-sense-10-data>head-descr-len
   w@ ." / Descr. Length: " .d
;

\ ***************************************************************************
\ SCSI-Command: READ (6)
\         Type: Block Command (SBC-3 clause 5.7)
\ ***************************************************************************
\ Forth Word:   scsi-build-read-6  ( block# #blocks cdb -- )
\ ***************************************************************************
\ this SCSI command uses 21 bits to represent start LBA
\ and 8 bits to specify the numbers of blocks to read
\ The value of 0 blocks is interpreted as 256 blocks
\
\ command code
08 CONSTANT scsi-cmd-read-6

\ CDB structure
STRUCT
   /c FIELD read-6>operation-code      \ 08h
   /c FIELD read-6>block-address-msb   \ upper 5 bits
   /w FIELD read-6>block-address       \ lower 16 bits
   /c FIELD read-6>length              \ number of blocks to read
   /c FIELD read-6>control             \ CDB control
CONSTANT scsi-length-read-6

: scsi-build-read-6                    ( block# #blocks cdb -- )
   >r                                  ( block# #blocks ) ( R: -- cdb )
   r@ scsi-length-read-6 erase         \ 6 bytes CDB
	scsi-cmd-read-6 r@ read-6>operation-code c! ( block# #blocks )

   \ check block count to read (#blocks)
   dup d# 255 >                        \ #blocks exceeded limit ?
   IF
      scsi-inc-errors
      drop 1                           \ replace with any valid number
   THEN
   r@ read-6>length c!                 \ set #blocks to read

   \ check starting block number (block#)
   dup 1fffff >                        \ check address upper limit
   IF
      scsi-inc-errors
      drop                             \ remove original block#
      1fffff                           \ replace with any valid address
   THEN
   dup d# 16 rshift
   r@ read-6>block-address-msb c!      \ set upper 5 bits
   ffff and
   r@ read-6>block-address w!                \ set lower 16 bits
   scsi-param-control r> read-6>control c!   ( R: cdb -- )
   scsi-length-read-6 to scsi-param-size     \ update CDB length
;

\ ***************************************************************************
\ SCSI-Command: READ (10)
\         Type: Block Command (SBC-3 clause 5.8)
\ ***************************************************************************
\ Forth Word:   scsi-build-read-10  ( block# #blocks cdb -- )
\ ***************************************************************************
\ command code
28 CONSTANT scsi-cmd-read-10

\ CDB structure
STRUCT
   /c FIELD read-10>operation-code
   /c FIELD read-10>protect
   /l FIELD read-10>block-address      \ logical block address (32bits)
   /c FIELD read-10>group
   /w FIELD read-10>length             \ transfer length (16-bits)
   /c FIELD read-10>control
CONSTANT scsi-length-read-10

: scsi-build-read-10                         ( block# #blocks cdb -- )
   >r                                        ( block# #blocks )  ( R: -- cdb )
   r@ scsi-length-read-10 erase             \ 10 bytes CDB
	scsi-cmd-read-10 r@ read-10>operation-code c! ( block# #blocks )
   r@ read-10>length w!                      ( block# )
   r@ read-10>block-address l!               (  )
   scsi-param-control r> read-10>control c!  ( R: cdb -- )
   scsi-length-read-10 to scsi-param-size    \ update CDB length
;

\ ***************************************************************************
\ SCSI-Command: READ (12)
\         Type: Block Command (SBC-3 clause 5.9)
\ ***************************************************************************
\ Forth Word:   scsi-build-read-12  ( block# #blocks cdb -- )
\ ***************************************************************************
\ command code
a8 CONSTANT scsi-cmd-read-12

\ CDB structure
STRUCT
   /c FIELD read-12>operation-code     \ code: a8
   /c FIELD read-12>protect            \ RDPROTECT, DPO, FUA, FUA_NV
   /l FIELD read-12>block-address      \ lba
   /l FIELD read-12>length             \ transfer length (32bits)
   /c FIELD read-12>group              \ group number
   /c FIELD read-12>control
CONSTANT scsi-length-read-12

: scsi-build-read-12                         ( block# #blocks cdb -- )
   >r                                        ( block# #blocks )  ( R: -- cdb )
   r@ scsi-length-read-12 erase             \ 12 bytes CDB
	scsi-cmd-read-12 r@ read-12>operation-code c! ( block# #blocks )
   r@ read-12>length l!                      ( block# )
   r@ read-12>block-address l!               (  )
   scsi-param-control r> read-12>control c!  ( R: cdb -- )
   scsi-length-read-12 to scsi-param-size    \ update CDB length
;

\ ***************************************************************************
\ SCSI-Command: READ with autodetection of required command
\               read(10) or read(12) depending on parameter size
\               (read(6) removed because obsolete in some cases (USB))
\         Type: Block Command
\ ***************************************************************************
\ Forth Word:   scsi-build-read?    ( block# #blocks cdb -- )
\
\                         +----------------+---------------------------|
\                         |  block# (lba)  |  #block (transfer-length) |
\             +-----------+----------------+---------------------------|
\             | read-6    |  16-Bits       |  8  Bits                  |
\             | read-10   |  32-Bits       |  16 Bits                  |
\             | read-12   |  32-Bits       |  32 Bits                  |
\ ***************************************************************************
: scsi-build-read?   ( block# #blocks cdb -- length )
   over              ( block# #blocks cdb #blocks )
   fffe >            \ tx-length (#blocks) exceeds 16-bit limit ?
   IF
      scsi-build-read-12   ( block# #blocks cdb -- )
      scsi-length-read-12  ( length )
   ELSE                    ( block# #blocks cdb )
      scsi-build-read-10   ( block# #blocks cdb -- )
      scsi-length-read-10  ( length )
   THEN
;

\ ***************************************************************************
\ SCSI-Command: START STOP UNIT
\         Type: Block Command (SBC-3 clause 5.19)
\ ***************************************************************************
\ Forth Word:   scsi-build-start-stop-unit  ( state# cdb -- )
\ ***************************************************************************
\ command code
1b CONSTANT scsi-cmd-start-stop-unit

\ CDB structure
STRUCT
   /c FIELD start-stop-unit>operation-code
   /c FIELD start-stop-unit>immed
   /w FIELD start-stop-unit>reserved
   /c FIELD start-stop-unit>pow-condition
   /c FIELD start-stop-unit>control
CONSTANT scsi-length-start-stop-unit

\ START/STOP constants
\ (see spec: SBC-3 clause 5.19)
f1 CONSTANT scsi-const-active-power    \ param used for start-stop-unit
f2 CONSTANT scsi-const-idle-power      \ param used for start-stop-unit
f3 CONSTANT scsi-const-standby-power   \ param used for start-stop-unit
3  CONSTANT scsi-const-load            \ param used for start-stop-unit
2  CONSTANT scsi-const-eject           \ param used for start-stop-unit
1  CONSTANT scsi-const-start
0  CONSTANT scsi-const-stop

: scsi-build-start-stop-unit                 ( state# cdb -- )
   >r                                        ( state# )  ( R: -- cdb )
   r@ scsi-length-start-stop-unit erase      \ 6 bytes CDB
	scsi-cmd-start-stop-unit r@ start-stop-unit>operation-code c!
   dup 3 >
   IF
      4 lshift                         \ shift to upper nibble
   THEN                                ( state )
   r@ start-stop-unit>pow-condition c!       (  )
   scsi-param-control r> start-stop-unit>control c!  ( R: cdb -- )
   scsi-length-start-stop-unit to scsi-param-size  \ update CDB length
;

\ ***************************************************************************
\ SCSI-Command: SEEK(10)
\         Type: Block Command (obsolete)
\ ***************************************************************************
\ Forth Word:   scsi-build-seek  ( state# cdb -- )
\ Obsolete function (last listed in spec SBC / Nov. 1997)
\ implemented only for the sake of completeness
\ ***************************************************************************
\ command code
2b CONSTANT scsi-cmd-seek

\ CDB structure
STRUCT
   /c FIELD seek>operation-code
   /c FIELD seek>reserved1
   /l FIELD seek>lba
   3  FIELD seek>reserved2
   /c FIELD seek>control
CONSTANT scsi-length-seek

: scsi-build-seek  ( lba cdb -- )
   >r              ( lba )  ( R: -- cdb )
   r@ scsi-length-seek erase           \ 10 bytes CDB
	scsi-cmd-seek r@ seek>operation-code c!
   r> seek>lba l!  (  )  ( R: cdb -- )
   scsi-length-seek to scsi-param-size \ update CDB length
;

\ ****************************************************************************
\ CDROM media event stuff
\ ****************************************************************************

STRUCT
    /w FIELD media-event-data-len
    /c FIELD media-event-nea-class
    /c FIELD media-event-supp-class
    /l FIELD media-event-data
CONSTANT scsi-length-media-event

: scsi-build-get-media-event                     ( cdb -- )
   dup c erase				         ( cdb )
   4a over c!				         ( cdb )
   01 over 1 + c!
   10 over 4 + c!
   08 over 8 + c!
   drop
;



\ ***************************************************************************
\ SCSI-Utility: .sense-code
\ ***************************************************************************
\ this utility prints a string associated to the sense code
\ see specs: SPC-3/r23 clause 4.5.6
\ ***************************************************************************
: .sense-text ( scode -- )
   case
      0    OF s" OK"               ENDOF
      1    OF s" RECOVERED ERR"    ENDOF
      2    OF s" NOT READY"        ENDOF
      3    OF s" MEDIUM ERROR"     ENDOF
      4    OF s" HARDWARE ERR"     ENDOF
      5    OF s" ILLEGAL REQUEST"  ENDOF
      6    OF s" UNIT ATTENTION"   ENDOF
      7    OF s" DATA PROTECT"     ENDOF
      8    OF s" BLANK CHECK"      ENDOF
      9    OF s" VENDOR SPECIFIC"  ENDOF
      a    OF s" COPY ABORTED"     ENDOF
      b    OF s" ABORTED COMMAND"  ENDOF
      d    OF s" VOLUME OVERFLOW"  ENDOF
      e    OF s" MISCOMPARE"       ENDOF
      dup  OF s" UNKNOWN"          ENDOF
   endcase
   5b emit type 5d emit
;

\ ***************************************************************************
\ SCSI-Utility: .status-code
\ ***************************************************************************
\ this utility prints a string associated to the status code
\ see specs: SAM-3/r14 clause 5.3
\ ***************************************************************************
: .status-text  ( stat -- )
   case
      00  OF s" GOOD"                  ENDOF
      02  OF s" CHECK CONDITION"       ENDOF
      04  OF s" CONDITION MET"         ENDOF
      08  OF s" BUSY"                  ENDOF
      18  OF s" RESERVATION CONFLICT"  ENDOF
      28  OF s" TASK SET FULL"         ENDOF
      30  OF s" ACA ACTIVE"            ENDOF
      40  OF s" TASK ABORTED"          ENDOF
      dup OF s" UNKNOWN"               ENDOF
   endcase
   5b emit type 5d emit
;

\ ***************************************************************************
\ SCSI-Utility: .capacity-text
\ ***************************************************************************
\ utility that shows total capacity on screen by use of the return data
\ from read-capacity calculation is SI conform (base 10)
\ ***************************************************************************
\ sub function to print a 3 digit decimal
\ number with 2 post decimal positions xxx.yy
: .dec3-2 ( prenum postnum -- )
   swap
   base @ >r                           \ save actual base setting
   decimal                             \ show decimal values
   4 .r 2e emit
   dup 9 <= IF 30 emit THEN .d         \ 3 pre-decimal, right aligned
   r> base !                           \ restore base
;

: .capacity-text  ( block-size #blocks -- )
   scsi-param-debug                    \ debugging flag set ?
   IF                                  \ show additional info
      2dup
      cr
      ." LBAs: " .d                    \ highest logical block number
      ." / Block-Size: " .d
      ." / Total Capacity: "
   THEN
   *                                   \ calculate total capacity
   dup d# 1000000000000 >=             \ check terabyte limit
   IF
      d# 1000000000000 /mod
      swap
      d# 10000000000 /                 \ limit remainder to two digits
      .dec3-2 ." TB"                   \ show terabytes as xxx.yy
   ELSE
      dup d# 1000000000 >=             \ check gigabyte limit
      IF
         d# 1000000000 /mod
         swap
         d# 10000000 /
         .dec3-2 ." GB"                \ show gigabytes as xxx.yy
      ELSE
         dup d# 1000000 >=
         IF
            d# 1000000 /mod            \ check mega byte limit
            swap
            d# 10000 /
            .dec3-2 ." MB"             \ show megabytes as xxx.yy
         ELSE
            dup d# 1000 >=             \ check kilo byte limit
            IF
               d# 1000 /mod
               swap
               d# 10 /
               .dec3-2 ." kB"
            ELSE
               .d ."  Bytes"
            THEN
         THEN
      THEN
   THEN
;

\ ***************************************************************************
\ SCSI-Utility: .inquiry-text  ( addr -- )
\ ***************************************************************************
\ utility that shows:
\     vendor-ident product-ident and revision
\ from an inquiry return data block (addr)
\ ***************************************************************************
: .inquiry-text  ( addr -- )
   22 emit     \ enclose text with "
   dup inquiry-data>vendor-ident      8 type space
   dup inquiry-data>product-ident    10 type space
       inquiry-data>product-revision  4 type
   22 emit
;

\ ***************************************************************************
\ SCSI-Utility: scsi-supp-init  ( -- )
\ ***************************************************************************
\ utility that helps to ensure that parameters are set to valid values
: scsi-supp-init  ( -- )
   false   to scsi-param-debug         \ no debug strings
   h# 0   to scsi-param-size
   h# 0   to scsi-param-control        \ common CDB control byte
   d# 0   to scsi-param-errors         \ local errors (param limits)
;

\ ***************************************************************************
\ Constants used by SCSI controller's execute-scsi-command
\ ***************************************************************************
true  CONSTANT scsi-dir-read
false CONSTANT scsi-dir-write


\ ***************************************************************************
\ scsi loader
\ ***************************************************************************
0 VALUE scsi-context                   \ addr of word list on top


\ ****************************************************************************
\ open scsi-support by adding a new word list on top of search path
\   precondition: scsi-support.fs must have been included
\ ****************************************************************************
: scsi-init  ( -- )
   also scsi-words                     \ append scsi word-list
   context  to scsi-context            \ save for close process
   scsi-supp-init                      \ preset all scsi-param-xxx values
   scsi-param-debug
   IF
      space ." SCSI-SUPPORT OPENED" cr
      .wordlists
   THEN
;

\ ****************************************************************************
\ close scsi-session and remove scsi word list (if exists)
\ ****************************************************************************
\ if 'previous' is used without a preceding 'also' all forth words are lost !
\ ****************************************************************************
: scsi-close  ( -- )
\ FIXME This only works if scsi-words is the last vocabulary on the stack
\       Instead we could use get-order to find us on the "wordlist stack",
\       remove us and write the wordlist stack back with set-order.
\       BUT: Is this worth the effort?

   scsi-param-debug
   IF
      space ." Closing SCSI-SUPPORT .. " cr
   THEN
   context scsi-context =              \ scsi word list still active ?
   IF
      scsi-param-errors 0<>          \ any errors occurred ?
      IF
         cr ." ** WARNING: " scsi-param-errors .d
         ." SCSI Errors occurred ** " cr
      THEN
      previous                         \ remove scsi word list on top
      0 to scsi-context                \ prevent from being misinterpreted
   ELSE
      cr ." ** WARNING: Trying to close non-open SCSI-SUPPORT (1) ** " cr
   THEN
   scsi-param-debug
   IF
     .wordlists
   THEN
;


s" scsi-init" $find drop               \ return execution pointer, when included

previous                               \ remove scsi word list from search path
definitions                            \ place next definitions into previous list

