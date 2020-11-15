\ *****************************************************************************
\ * Copyright (c) 2012 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

." Populating " pwd cr

FALSE CONSTANT virtio-scsi-debug

2 encode-int s" #address-cells" property
0 encode-int s" #size-cells" property

: decode-unit 2 hex64-decode-unit ;
: encode-unit 2 hex64-encode-unit ;

FALSE VALUE initialized?

/vd-len BUFFER: virtiodev
virtiodev virtio-setup-vd

STRUCT \ virtio-scsi-config
    /l FIELD vs-cfg>num-queues
    /l FIELD vs-cfg>seg-max
    /l FIELD vs-cfg>max-sectors
    /l FIELD vs-cfg>cmd-per-lun
    /l FIELD vs-cfg>event-info-size
    /l FIELD vs-cfg>sense_size
    /l FIELD vs-cfg>cdb-size
    /w FIELD vs-cfg>max-channel
    /w FIELD vs-cfg>max-target
    /l FIELD vs-cfg>max-lun
CONSTANT vs-cfg-length

STRUCT \ virtio-scsi-req
    8  FIELD vs-req>lun
    8  FIELD vs-req>tag
    /c FIELD vs-req>task-attr
    /c FIELD vs-req>prio
    /c FIELD vs-req>crn
    20 FIELD vs-req>cdb
CONSTANT vs-req-length

STRUCT \ virtio-scsi-resp
    /l FIELD vs-rsp>sense-len
    /l FIELD vs-rsp>residual
    /w FIELD vs-rsp>status-qualifier
    /c FIELD vs-rsp>status
    /c FIELD vs-rsp>response
    60 FIELD vs-rsp>sense
CONSTANT vs-rsp-length

CREATE vs-req vs-req-length allot
CREATE vs-rsp vs-rsp-length allot

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

: execute-scsi-command ( buf-addr buf-len dir cmd-addr cmd-len -- ... )
                       ( ... [ sense-buf sense-len ] stat )
    \ Cleanup virtio request and response
    vs-req vs-req-length erase
    vs-rsp vs-rsp-length erase

    \ Populate the request
    current-target vs-req vs-req>lun x!
    vs-req vs-req>cdb swap move

    \ Send it
    vs-req vs-rsp virtiodev
    virtio-scsi-send

    0 <> IF
        ." VIRTIO-SCSI: Queuing failure !" cr
        0 0 -1 EXIT
    THEN

    \ Check virtio response
    vs-rsp vs-rsp>response c@ CASE
        0 OF ENDOF			\ Good
        5 OF drop 0 0 8 EXIT ENDOF	\ Busy
        dup OF 0 0 -1 EXIT ENDOF	\ Anything else -> HW error
    ENDCASE

    \ Other error status
    vs-rsp vs-rsp>status c@ dup 0<> IF
        vs-rsp vs-rsp>sense-len l@ dup 0= IF
            \ This relies on auto-sense from qemu... if that isn't always the
            \ case we should request sense here
            ." VIRTIO-SCSI: No sense data" cr
	    0 EXIT
        THEN
        vs-rsp vs-rsp>sense swap
        virtio-scsi-debug IF
            over scsi-get-sense-data
            ." VIRTIO-SCSI: Sense key [ " dup . ." ] " .sense-text
	    ."  ASC,ASCQ: " . . cr
        THEN
       rot
    THEN    
;

\ --------------------------------
\ Include the generic host helpers
\ --------------------------------

" scsi-host-helpers.fs" included

\ FIXME: Check max transfer coming from virtio config
: max-transfer ( -- n )
    10000 \ Larger value seem to have problems with some CDROMs
;

\ -----------------------------------------------------------
\ SCSI scan at boot and child device support
\ -----------------------------------------------------------

\ We use SRP luns of the form 01000000 | (target << 16) | lun
\ in the top 32 bits of the 64-bit LUN
: (set-target)
    to current-target
;

: dev-generate-srplun ( target lun-id -- srplun )
    swap 0100 or 10 << or 20 <<
;

\ We obtain here a unit address on the stack, since our #address-cells
\ is 2, the 64-bit srplun is split in two cells that we need to join
\
\ Note: This diverges a bit from the original OF scsi spec as the two
\ cells are the 2 words of a 64-bit SRP LUN
: set-address ( srplun.lo srplun.hi -- )
    lxjoin (set-target)
;

100 CONSTANT #target
: dev-max-target ( -- #target )
    #target
;

" scsi-probe-helpers.fs" included

scsi-close        \ no further scsi words required

0 VALUE queue-control-addr
0 VALUE queue-event-addr
0 VALUE queue-cmd-addr

: setup-virt-queues
    \ add 3 queues 0-controlq, 1-eventq, 2-cmdq
    \ fixme: do we need to find more than the above 3 queues if exists
    virtiodev 0 virtio-get-qsize virtio-vring-size
    alloc-mem to queue-control-addr
    virtiodev 0 queue-control-addr virtio-set-qaddr

    virtiodev 1 virtio-get-qsize virtio-vring-size
    alloc-mem to queue-event-addr
    virtiodev 1 queue-event-addr virtio-set-qaddr

    virtiodev 2 virtio-get-qsize virtio-vring-size
    alloc-mem to queue-cmd-addr
    virtiodev 2 queue-cmd-addr virtio-set-qaddr
;

\ Set scsi alias if none is set yet
: setup-alias
    s" scsi" find-alias 0= IF
	s" scsi" get-node node>path set-alias
    ELSE
	drop
    THEN
;

: shutdown ( -- )
    initialized? IF
       my-phandle node>path open-dev ?dup IF
          virtiodev virtio-scsi-shutdown
          close-dev
       THEN
       FALSE to initialized?
    THEN
;

: virtio-scsi-init-and-scan  ( -- )
    \ Create instance for scanning:
    0 0 get-node open-node ?dup 0= IF ." exiting " cr EXIT THEN
    my-self >r
    dup to my-self
    \ Scan the VSCSI bus:
    virtiodev virtio-scsi-init
    0= IF
	setup-virt-queues
	scsi-find-disks
	setup-alias
	TRUE to initialized?
	['] shutdown add-quiesce-xt
    THEN
    \ Close the temporary instance:
    close-node
    r> to my-self
;

: virtio-scsi-add-disk
    " scsi-disk.fs" included
;

virtio-scsi-add-disk
virtio-scsi-init-and-scan
