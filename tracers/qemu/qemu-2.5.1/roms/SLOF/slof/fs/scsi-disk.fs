\ *****************************************************************************
\ * Copyright (c) 2011 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ Create new VSCSI child device

\ Create device
new-device

\ Set name
s" disk" device-name

s" block" device-type

false VALUE scsi-disk-debug?

\ Get SCSI bits
scsi-open

\ Send SCSI commands to controller

: execute-scsi-command ( buf-addr buf-len dir cmd-addr cmd-len -- ... )
                       ( ... [ sense-buf sense-len ] stat )
    " execute-scsi-command" $call-parent
;

: retry-scsi-command ( buf-addr buf-len dir cmd-addr cmd-len #retries -- ... )
                     ( ... 0 | [ sense-buf sense-len ] stat )
    " retry-scsi-command" $call-parent
;

\ ---------------------------------\
\ Common SCSI Commands and helpers \
\ ---------------------------------\

0 INSTANCE VALUE block-size
0 INSTANCE VALUE max-transfer
0 INSTANCE VALUE max-block-num
0 INSTANCE VALUE is_cdrom
INSTANCE VARIABLE deblocker

\ This scratch area is made global for now as we only
\ use it for small temporary commands such as inquiry
\ read-capacity or media events
CREATE scratch 100 allot
CREATE cdb 10 allot

: dump-scsi-error ( sense-buf sense-len stat name namelen -- )
    ." SCSI-DISK: " my-self instance>path type ." ," type ."  failed" cr
    ." SCSI-DISK: Status " dup . .status-text
    0<> IF
        ."  Sense " scsi-get-sense-data dup . .sense-text
	."  ASC " . ." ASCQ " . cr
    ELSE drop THEN
;

: read-blocks ( addr block# #blocks -- #read )
    scsi-disk-debug? IF
        ." SCSI-DISK: read-blocks " .s cr
    THEN

    \ Bound check. This should probably be done by deblocker
    \ but it doesn't at this point so do it here
    2dup + max-block-num > IF
        ." SCSI-DISK: Access beyond end of device ! " cr
	drop
	dup max-block-num > IF
	  drop drop 0 EXIT
	THEN
	dup max-block-num swap -
    THEN

    dup block-size *                            ( addr block# #blocks len )
    >r rot r> 			                ( block# #blocks addr len )
    2swap                                       ( addr len block# #blocks )
    dup >r
    cdb scsi-build-read-10                      ( addr len )
    r> -rot                                     ( #blocks addr len )
    scsi-dir-read cdb scsi-param-size 10
    retry-scsi-command
                                                ( #blocks [ sense-buf sense-len ] stat )
    dup 0<> IF " read-blocks" dump-scsi-error -65 throw ELSE drop THEN
;

: (inquiry) ( size -- buffer | NULL )
    dup cdb scsi-build-inquiry
    \ 16 retries for inquiry to flush out any UAs
    scratch swap scsi-dir-read cdb scsi-param-size 10 retry-scsi-command
    \ Success ?
    0= IF scratch ELSE 2drop 0 THEN
;

: inquiry ( -- buffer | NULL )
    scsi-disk-debug? IF
	." SCSI-DISK: inquiry " .s cr
    THEN
    d# 36 (inquiry) 0= IF 0 EXIT THEN
    scratch inquiry-data>add-length c@ 5 +
    (inquiry)
;

: read-capacity ( -- blocksize #blocks )
    \ Now issue the read-capacity command
    scsi-disk-debug? IF
        ." SCSI-DISK: read-capacity " .s cr
    THEN
    \ Make sure that there are zeros in the buffer in case something goes wrong:
    scratch 10 erase
    cdb scsi-build-read-cap-10 scratch scsi-length-read-cap-10-data scsi-dir-read
    cdb scsi-param-size 1 retry-scsi-command
    \ Success ?
    dup 0<> IF " read-capacity" dump-scsi-error 0 0 EXIT THEN
    drop scratch scsi-get-capacity-10 1 +
;

100 CONSTANT test-unit-retries

\ SCSI test-unit-read
: test-unit-ready ( true | [ ascq asc sense-key false ] )
    scsi-disk-debug? IF
        ." SCSI-DISK: test-unit-ready " .s cr
    THEN
    cdb scsi-build-test-unit-ready
    0 0 0 cdb scsi-param-size test-unit-retries retry-scsi-command
    \ stat == 0, return
    0= IF true EXIT THEN
    \ check sense len, no sense -> return HW error
    0= IF drop 0 0 4 false EXIT THEN
    \ get sense
    scsi-get-sense-data false
;


: start-stop-unit ( state# -- true | false )
    scsi-disk-debug? IF
        ." SCSI-DISK: start-stop-unit " .s cr
    THEN
    cdb scsi-build-start-stop-unit
    0 0 0 cdb scsi-param-size 10 retry-scsi-command
    \ Success ?
    0= IF true ELSE 2drop false THEN
;

: compare-sense ( ascq asc key ascq2 asc2 key2 -- true | false )
    3 pick =	    ( ascq asc key ascq2 asc2 keycmp )
    swap 4 pick =   ( ascq asc key ascq2 keycmp asccmp )
    rot 5 pick =    ( ascq asc key keycmp asccmp ascqcmp )
    and and nip nip nip
;

\ -------------------------\
\ CDROM specific functions \
\ -------------------------\

0 CONSTANT CDROM-READY
1 CONSTANT CDROM-NOT-READY
2 CONSTANT CDROM-NO-DISK
3 CONSTANT CDROM-TRAY-OPEN
4 CONSTANT CDROM-INIT-REQUIRED
5 CONSTANT CDROM-TRAY-MAYBE-OPEN

: cdrom-try-close-tray ( -- )
    scsi-const-load start-stop-unit drop
;

: cdrom-must-close-tray ( -- )
    scsi-const-load start-stop-unit not IF
        ." Tray open !" cr -65 throw
    THEN
;

: get-media-event ( -- true | false )
    scsi-disk-debug? IF
        ." SCSI-DISK: get-media-event " .s cr
    THEN
    cdb scsi-build-get-media-event
    scratch scsi-length-media-event scsi-dir-read cdb scsi-param-size 1 retry-scsi-command
    \ Success ?
    0= IF true ELSE 2drop false THEN
;

: cdrom-status ( -- status )
    test-unit-ready
    IF CDROM-READY EXIT THEN

    scsi-disk-debug? IF
        ." TestUnitReady sense: " 3dup . . . cr
    THEN

    3dup 1 4 2 compare-sense IF
        3drop CDROM-NOT-READY EXIT
    THEN

    get-media-event IF
        scratch w@ 4 >= IF
	    scratch 2 + c@ 04 = IF
	        scratch 5 + c@
		dup 02 and 0<> IF drop 3drop CDROM-READY EXIT THEN
		dup 01 and 0<> IF drop 3drop CDROM-TRAY-OPEN EXIT THEN
		drop 3drop CDROM-NO-DISK EXIT
	    THEN
	THEN
    THEN

    3dup 2 4 2 compare-sense IF
        3drop CDROM-INIT-REQUIRED EXIT
    THEN
    over 4 = over 2 = and IF
        \ Format in progress... what do we do ? Just ignore
	3drop CDROM-READY EXIT
    THEN
    over 3a = IF
        3drop CDROM-NO-DISK EXIT
    THEN

    \ Other error...
    3drop CDROM-TRAY-MAYBE-OPEN
;

: prep-cdrom ( -- ready? )
    5 0 DO
        cdrom-status CASE
	    CDROM-READY           OF UNLOOP true EXIT ENDOF
	    CDROM-NO-DISK         OF ." No medium !" cr UNLOOP false EXIT ENDOF
	    CDROM-TRAY-OPEN       OF cdrom-must-close-tray ENDOF
	    CDROM-INIT-REQUIRED   OF cdrom-try-close-tray ENDOF
	    CDROM-TRAY-MAYBE-OPEN OF cdrom-try-close-tray ENDOF
	ENDCASE
	d# 1000 ms
    LOOP
    ." Drive not ready !" cr false
;

\ ------------------------\
\ Disk specific functions \
\ ------------------------\

: prep-disk ( -- ready? )
    test-unit-ready not IF
        ." SCSI-DISK: Disk not ready ! "
        ." Sense " dup .sense-text ." [" . ." ]"
	."  ASC " . ."  ASCQ " . cr
	false EXIT THEN true
;

\ --------------------------\
\ Standard device interface \
\ --------------------------\

: open ( -- true | false )
    scsi-disk-debug? IF
        ." SCSI-DISK: open [" .s ." ] unit is " my-unit . . ."  [" .s ." ]" cr
    THEN
    my-unit " set-address" $call-parent

    inquiry dup 0= IF drop false EXIT THEN
    scsi-disk-debug? IF
        ." ---- inquiry: ----" cr
        dup 100 dump cr
        ." ------------------" cr
    THEN

    \ Skip devices with PQ != 0
    dup inquiry-data>peripheral c@ e0 and 0 <> IF
        ." SCSI-DISK: Unsupported PQ != 0" cr
	false EXIT
    THEN

    inquiry-data>peripheral c@ CASE
        5   OF true to is_cdrom ENDOF
        7   OF true to is_cdrom ENDOF
    ENDCASE

    scsi-disk-debug? IF
        is_cdrom IF
            ." SCSI-DISK: device treated as CD-ROM" cr
        ELSE
            ." SCSI-DISK: device treated as disk" cr
        THEN
    THEN

    is_cdrom IF prep-cdrom ELSE prep-disk THEN
    not IF false EXIT THEN

    " max-transfer" $call-parent to max-transfer

    read-capacity to max-block-num to block-size
    max-block-num 0= block-size 0= OR IF
       ." SCSI-DISK: Failed to get disk capacity!" cr
       FALSE EXIT
    THEN

    scsi-disk-debug? IF
        ." Capacity: " max-block-num . ." blocks of " block-size . cr
    THEN

    0 0 " deblocker" $open-package dup deblocker ! dup IF 
        " disk-label" find-package IF
            my-args rot interpose
        THEN
   THEN 0<>
;

: close ( -- )
    deblocker @ close-package ;

: seek ( pos.lo pos.hi -- status )
    s" seek" deblocker @ $call-method ;

: read ( addr len -- actual )
    s" read" deblocker @ $call-method ;

\ Get rid of SCSI bits
scsi-close

finish-device
