\ *****************************************************************************
\ * Copyright (c) 2013 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ ( usbdev -- )

new-device

VALUE usbdev

s" slofdev.fs" included

false VALUE usb-disk-debug?

usbdev slof-dev>port l@ dup set-unit encode-phys " reg" property
s" storage" device-name

s" dev-parent-calls.fs" included

2 encode-int s" #address-cells" property
0 encode-int s" #size-cells" property

: decode-unit 2 hex64-decode-unit ;
: encode-unit 2 hex64-encode-unit ;

0 CONSTANT USB_PIPE_OUT
1 CONSTANT USB_PIPE_IN

\ -----------------------------------------------------------
\ Specific properties
\ -----------------------------------------------------------

usbdev slof-dev>udev @ VALUE udev
usbdev slof-dev>port l@ VALUE port
usbdev slof-dev>hcitype l@ VALUE hcitype

0 INSTANCE VALUE lun
10000 VALUE dev-max-transfer
0     VALUE resp-buffer
0     VALUE resp-size
0f CONSTANT SCSI-COMMAND-OFFSET

\ -------------------------------------------------------
\ DMA-able buffers
\ -------------------------------------------------------

STRUCT
   dev-max-transfer FIELD usb>data
   40 FIELD usb>cmd
   20 FIELD usb>csw
CONSTANT /dma-buf

0 VALUE dma-buf
0 VALUE dma-buf-phys
0 VALUE td-buf
0 VALUE td-buf-phys
1000 CONSTANT /td-buf

: (dma-buf-init)  ( -- )
   /dma-buf dma-alloc TO dma-buf
   dma-buf /dma-buf 0 dma-map-in TO dma-buf-phys
   /td-buf dma-alloc TO td-buf
   td-buf /td-buf 0 dma-map-in TO td-buf-phys
;

: (dma-buf-free)  ( -- )
   td-buf td-buf-phys /td-buf dma-map-out
   td-buf /td-buf dma-free
   0 TO td-buf
   0 TO td-buf-phys
   dma-buf dma-buf-phys /dma-buf dma-map-out
   dma-buf /dma-buf dma-free
   0 TO dma-buf
   0 TO dma-buf-phys
;


scsi-open

\ -----------------------------------------------------------
\ Perform SCSI commands
\ -----------------------------------------------------------

0 INSTANCE VALUE current-target

\ SCSI command. We do *NOT* implement the "standard" execute-command
\ because that doesn't have a way to return the sense buffer back, and
\ we do have auto-sense with some hosts. Instead we implement a made-up
\ do-scsi-command.
\
\ Note: stat is -1 for "hw error" (ie, error queuing the command or
\ getting the response).
\
\ A sense buffer is returned whenever the status is non-0 however
\ if sense-len is 0 then no sense data is actually present
\

: do-bulk-command ( resp-buffer resp-size -- TRUE | FALSE )
    TO resp-size
    TO resp-buffer
    udev USB_PIPE_OUT td-buf td-buf-phys dma-buf-phys usb>cmd 1F
    usb-transfer-bulk IF \ transfer CBW
	resp-size IF
	    d# 125 us
	    udev USB_PIPE_IN td-buf td-buf-phys resp-buffer resp-size
	    usb-transfer-bulk 1 = not IF \ transfer data
	        usb-disk-debug?	IF ." Data phase failed " cr THEN
		\ FALSE EXIT
		\ in case of a stall/halted endpoint we clear the halt
		\ Fall through and try reading the CSW
	    THEN
	THEN
	d# 125 us
	udev USB_PIPE_IN td-buf td-buf-phys dma-buf-phys usb>csw 0D
	usb-transfer-bulk \ transfer CSW
    ELSE
	FALSE EXIT
    THEN
;

STRUCT \ cbw
    /l FIELD cbw>sig
    /l FIELD cbw>tag
    /l FIELD cbw>len
    /c FIELD cbw>flags
    /c FIELD cbw>lun     \ 0:3 bits
    /c FIELD cbw>cblen   \ 0:4 bits
CONSTANT cbw-length

STRUCT \ csw
    /l FIELD csw>sig
    /l FIELD csw>tag
    /l FIELD csw>data-residue
    /c FIELD csw>status
CONSTANT cbw-length

0 VALUE cbw-addr
0 VALUE csw-addr

: build-cbw ( tag xfer-len dir lun cmd-len addr -- )
    TO cbw-addr               ( tag xfer-len dir lun cmd-len )
    cbw-addr cbw-length erase ( tag xfer-len dir lun cmd-len )
    cbw-addr cbw>cblen c!     ( tag xfer-len dir lun )
    cbw-addr cbw>lun c!       ( tag xfer-len dir )
    \ dir is true or false
    \ bmCBWFlags
    \           BIT 7 Direction
    \               0 - OUT
    \               1 - IN
    IF 80 ELSE 0 THEN
    cbw-addr cbw>flags c!     ( tag xfer-len )
    cbw-addr cbw>len l!-le    ( tag )
    cbw-addr cbw>tag l!-le    ( )
    43425355 cbw-addr cbw>sig l!-le
;

0 INSTANCE VALUE usb-buf-addr
0 INSTANCE VALUE usb-buf-len
0 INSTANCE VALUE usb-dir
0 INSTANCE VALUE usb-cmd-addr
0 INSTANCE VALUE usb-cmd-len
1 VALUE tag

: execute-scsi-command ( buf-addr buf-len dir cmd-addr cmd-len -- ... )
                       ( ... [ sense-buf sense-len ] stat )
    \ Cleanup virtio request and response
    to usb-cmd-len to usb-cmd-addr to usb-dir to usb-buf-len to usb-buf-addr

    dma-buf usb>cmd 40 0 fill
    dma-buf usb>csw 20 0 fill

    tag usb-buf-len usb-dir lun usb-cmd-len dma-buf usb>cmd
    ( tag transfer-len dir lun cmd-len addr )
    build-cbw
    1 tag + to tag

    usb-cmd-addr
    dma-buf usb>cmd SCSI-COMMAND-OFFSET +
    usb-cmd-len
    move

    \ Send it
    dma-buf-phys usb>data usb-buf-len
    do-bulk-command IF
	dma-buf usb>data usb-buf-addr usb-buf-len move
    ELSE
        ." USB-DISK: Bulk commad failed!" cr
        0 0 -1 EXIT
    THEN

    dma-buf usb>csw to csw-addr
    csw-addr csw>sig l@ 55534253 <> IF
	." USB-DISK: CSW signature invalid " cr
	0 0 -1 EXIT
    THEN

    csw-addr csw>status c@ CASE
	0 OF ENDOF			\ Good
	1 OF
	    usb-disk-debug? IF
		." USB-DISK: CSW Data residue: "
		csw-addr csw>data-residue l@-le . cr
	    THEN
	    0 0 8 EXIT ENDOF	\ Command failed, Retry
	dup OF 0 0 -1 EXIT ENDOF	\ Anything else -> HW error
    ENDCASE

    \ Other error status
    csw-addr csw>status c@ dup 0<> IF
	usb-disk-debug? IF
	    over scsi-get-sense-data
	    ." USB-DISK: Sense key [ " dup . ." ] " .sense-text
	    ."  ASC,ASCQ: " . . cr
        THEN
       rot
    THEN
;

\ --------------------------------
\ Include the generic host helpers
\ --------------------------------

" scsi-host-helpers.fs" included

0 VALUE open-count

: usb-storage-init  (  -- TRUE )
    td-buf 0= IF
	usb-disk-debug? IF ." USB-DISK: Allocating buffer "  cr THEN
	(dma-buf-init)
	udev USB-MSC-INIT 0= IF
	    ." USB-DISK: Unable to initialize MSC " cr
	    FALSE
	ELSE
	    TRUE
	THEN
    THEN
;

: usb-storage-cleanup
    td-buf 0<> IF
	usb-disk-debug? IF ." USB-DISK: Freeing buffer " cr THEN
	(dma-buf-free)
	udev USB-MSC-EXIT 0= IF ." USB-DISK: Unable to exit MSC " cr THEN
    THEN
;

: open
    usb-disk-debug? IF ." USB-DISK: Opening (count is " open-count . ." )" cr THEN

    open-count 0= IF
	usb-storage-init IF
	    1 to open-count true
	ELSE ." USB-DISK initialization failed !" cr false THEN
    ELSE
	open-count 1 + to open-count
	true
    THEN
;

: close
    usb-disk-debug? IF ." USB-DISK: Closing (count is " open-count . ." )" cr THEN

    open-count 0> IF
        open-count 1 - dup to open-count
	0= IF
	    usb-storage-cleanup
	THEN
    THEN
;

\ -----------------------------------------------------------
\ SCSI scan at boot and child device support
\ -----------------------------------------------------------

\ We use SRP luns of the form 01000000 | (target << 8) | lun
\ in the top 32 bits of the 64-bit LUN
: (set-target)
    dup 20 >> FFFF and to lun
    dup 30 >> FF and to port
    to current-target
    usb-disk-debug? IF ." USB-DISK: udev " udev . ." lun:" lun . ." port:" port . cr THEN
;

: dev-generate-srplun ( target lun-id -- srplun )
    swap drop port 0100 or 10 << or 20 <<
;

\ FIXME: Check max transfer coming from virtio config
: max-transfer ( -- n )
    dev-max-transfer
;

\ We obtain here a unit address on the stack, since our #address-cells
\ is 2, the 64-bit srplun is split in two cells that we need to join
\
\ Note: This diverges a bit from the original OF scsi spec as the two
\ cells are the 2 words of a 64-bit SRP LUN
: set-address ( srplun.lo srplun.hi -- )
    lxjoin (set-target)
    usb-disk-debug? IF ." USB-DISK: udev " udev . ." lun:" lun . ." port:" port . cr THEN
;

1 CONSTANT #target
: dev-max-target ( -- #target )
    #target
;

" scsi-probe-helpers.fs" included

scsi-close        \ no further scsi words required

\ Set scsi alias if none is set yet
: setup-alias
    s" scsi" find-alias 0= IF
	s" scsi" get-node node>path set-alias
    ELSE
	drop
    THEN
;

: usb-storage-init-and-scan ( -- )
   usb-disk-debug? IF ." Initializing usb-disk: udev " udev . cr THEN

  \ Create instance for scanning:
   0 0 get-node open-node ?dup 0= IF EXIT THEN
   my-self >r
   dup to my-self

   hcitype
   CASE
      1 OF 4000 TO dev-max-transfer ENDOF \ OHCI
      2 OF 10000 TO dev-max-transfer ENDOF \ EHCI
      3 OF F000 TO dev-max-transfer ENDOF \ XHCI
   ENDCASE
   usb-storage-init
   scsi-find-disks
   setup-alias
   usb-storage-cleanup
   \ Close the temporary instance:
   close-node
   r> to my-self
;

."     USB Storage " cr
: usb-scsi-add-disk
     " scsi-disk.fs" included
;

usb-scsi-add-disk
usb-storage-init-and-scan

finish-device
