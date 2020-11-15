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

." Populating " pwd

false VALUE vscsi-debug?
0 VALUE vscsi-unit

\ -----------------------------------------------------------
\ Direct DMA conversion hack
\ -----------------------------------------------------------
: l2dma ( laddr - dma_addr)      
;

\ -----------------------------------------------------------
\ CRQ related functions
\ -----------------------------------------------------------

0    VALUE     crq-real-base
0    VALUE     crq-base
0    VALUE     crq-dma
0    VALUE     crq-offset
1000 CONSTANT  CRQ-SIZE

CREATE crq 10 allot

: crq-alloc ( -- )
    \ Allocate enough to align to a page
    CRQ-SIZE fff + alloc-mem to crq-real-base
    \ align the result
    crq-real-base fff + fffff000 AND to crq-base 0 to crq-offset
    crq-base l2dma to crq-dma
;

: crq-free ( -- )
    vscsi-unit hv-free-crq
    crq-real-base CRQ-SIZE fff + free-mem 0 to crq-base 0 to crq-real-base
;

: crq-init ( -- res )
    \ Allocate CRQ. XXX deal with fail
    crq-alloc

    vscsi-debug? IF
        ." VSCSI: allocated crq at " crq-base . cr
    THEN

    \ Clear buffer
    crq-base CRQ-SIZE erase

    \ Register with HV
    vscsi-unit crq-dma CRQ-SIZE hv-reg-crq

    \ Fail case
    dup 0 <> IF
        ." VSCSI: Error " . ."  registering CRQ !" cr
	crq-free
    THEN
;

: crq-cleanup ( -- )
    crq-base 0 = IF EXIT THEN

    vscsi-debug? IF
        ." VSCSI: freeing crq at " crq-base . cr
    THEN
    crq-free
;

: crq-send ( msgaddr -- true | false )
    vscsi-unit swap hv-send-crq 0 =
;

: crq-poll ( -- true | false)
    crq-offset crq-base + dup
    vscsi-debug? IF
        ." VSCSI: crq poll " dup .
    THEN
    c@
    vscsi-debug? IF
        ."  value=" dup . cr
    THEN
    80 and 0 <> IF
        dup crq 10 move
	0 swap c!
	crq-offset 10 + dup CRQ-SIZE >= IF drop 0 THEN to crq-offset
	true
    ELSE drop false THEN
;

: crq-wait ( -- true | false)
    \ FIXME: Add timeout
    0 BEGIN drop crq-poll dup not WHILE d# 1 ms REPEAT
    dup not IF
        ." VSCSI: Timeout waiting response !" cr EXIT
    ELSE
        vscsi-debug? IF
            ." VSCSI: got crq: " crq dup l@ . ."  " 4 + dup l@ . ."  "
	    4 + dup l@ . ."  " 4 + l@ . cr
        THEN
    THEN
;

\ -----------------------------------------------------------
\ CRQ encapsulated SRP definitions
\ -----------------------------------------------------------

01 CONSTANT VIOSRP_SRP_FORMAT
02 CONSTANT VIOSRP_MAD_FORMAT
03 CONSTANT VIOSRP_OS400_FORMAT
04 CONSTANT VIOSRP_AIX_FORMAT
06 CONSTANT VIOSRP_LINUX_FORMAT
07 CONSTANT VIOSRP_INLINE_FORMAT

struct
   1 field >crq-valid
   1 field >crq-format
   1 field >crq-reserved
   1 field >crq-status
   2 field >crq-timeout
   2 field >crq-iu-len
   8 field >crq-iu-data-ptr
constant /crq

: srp-send-crq ( addr len -- )
    80                crq >crq-valid c!
    VIOSRP_SRP_FORMAT crq >crq-format c!
    0                 crq >crq-reserved c!
    0                 crq >crq-status c!
    0                 crq >crq-timeout w!
    ( len )           crq >crq-iu-len w!
    ( addr ) l2dma    crq >crq-iu-data-ptr x!
    crq crq-send
    not IF
        ." VSCSI: Error sending CRQ !" cr
    THEN
;

: srp-wait-crq ( -- [tag true] | false )
    crq-wait not IF false EXIT THEN

    crq >crq-format c@ VIOSRP_SRP_FORMAT <> IF
    	." VSCSI: Unsupported SRP response: "
	crq >crq-format c@ . cr
	false EXIT
    THEN

    crq >crq-iu-data-ptr x@ true
;

\ Add scsi functions to dictionary
scsi-open


\ -----------------------------------------------------------
\ SRP definitions
\ -----------------------------------------------------------

0 VALUE >srp_opcode

00 CONSTANT SRP_LOGIN_REQ
01 CONSTANT SRP_TSK_MGMT
02 CONSTANT SRP_CMD
03 CONSTANT SRP_I_LOGOUT
c0 CONSTANT SRP_LOGIN_RSP
c1 CONSTANT SRP_RSP
c2 CONSTANT SRP_LOGIN_REJ
80 CONSTANT SRP_T_LOGOUT
81 CONSTANT SRP_CRED_REQ
82 CONSTANT SRP_AER_REQ
41 CONSTANT SRP_CRED_RSP
42 CONSTANT SRP_AER_RSP

02 CONSTANT SRP_BUF_FORMAT_DIRECT
04 CONSTANT SRP_BUF_FORMAT_INDIRECT

struct
   1 field >srp-login-opcode
   3 +
   8 field >srp-login-tag
   4 field >srp-login-req-it-iu-len
   4 +
   2 field >srp-login-req-buf-fmt
   1 field >srp-login-req-flags
   5 +
  10 field >srp-login-init-port-ids
  10 field >srp-login-trgt-port-ids
constant /srp-login

struct
   1 field >srp-lresp-opcode
   3 +
   4 field >srp-lresp-req-lim-delta
   8 field >srp-lresp-tag
   4 field >srp-lresp-max-it-iu-len
   4 field >srp-lresp-max-ti-iu-len
   2 field >srp-lresp-buf-fmt
   1 field >srp-lresp-flags
constant /srp-login-resp

struct
   1 field >srp-lrej-opcode
   3 +
   4 field >srp-lrej-reason
   8 field >srp-lrej-tag
   8 +
   2 field >srp-lrej-buf-fmt
constant /srp-login-rej

00 CONSTANT SRP_NO_DATA_DESC
01 CONSTANT SRP_DATA_DESC_DIRECT
02 CONSTANT SRP_DATA_DESC_INDIRECT

struct
    1 field >srp-cmd-opcode
    1 field >srp-cmd-sol-not
    3 +
    1 field >srp-cmd-buf-fmt
    1 field >srp-cmd-dout-desc-cnt
    1 field >srp-cmd-din-desc-cnt
    8 field >srp-cmd-tag
    4 +
    8 field >srp-cmd-lun
    1 +
    1 field >srp-cmd-task-attr
    1 +
    1 field >srp-cmd-add-cdb-len
   10 field >srp-cmd-cdb
    0 field >srp-cmd-cdb-add
constant /srp-cmd

struct
    1 field >srp-rsp-opcode
    1 field >srp-rsp-sol-not
    2 +
    4 field >srp-rsp-req-lim-delta
    8 field >srp-rsp-tag
    2 +
    1 field >srp-rsp-flags
    1 field >srp-rsp-status
    4 field >srp-rsp-dout-res-cnt
    4 field >srp-rsp-din-res-cnt
    4 field >srp-rsp-sense-len
    4 field >srp-rsp-resp-len
    0 field >srp-rsp-data
constant /srp-rsp

\ Constants for srp-rsp-flags
01 CONSTANT SRP_RSP_FLAG_RSPVALID
02 CONSTANT SRP_RSP_FLAG_SNSVALID
04 CONSTANT SRP_RSP_FLAG_DOOVER
05 CONSTANT SRP_RSP_FLAG_DOUNDER
06 CONSTANT SRP_RSP_FLAG_DIOVER
07 CONSTANT SRP_RSP_FLAG_DIUNDER

\ Storage for up to 256 bytes SRP request */
CREATE srp 100 allot
0 VALUE srp-len

: srp-prep-cmd-nodata ( srplun -- )
    srp /srp-cmd erase
    SRP_CMD srp >srp-cmd-opcode c!
    1 srp >srp-cmd-tag x!
    srp >srp-cmd-lun x!         \ 8 bytes lun
    /srp-cmd to srp-len   
;

: srp-prep-cmd-io ( addr len srplun -- )
    srp-prep-cmd-nodata		( addr len )
    swap l2dma			( len dmaaddr )
    srp srp-len +    		( len dmaaddr descaddr )
    dup >r x! r> 8 +		( len descaddr+8 )
    dup 0 swap l! 4 +		( len descaddr+c )
    l!    
    srp-len 10 + to srp-len
;

: srp-prep-cmd-read ( addr len srplun -- )
    srp-prep-cmd-io
    01 srp >srp-cmd-buf-fmt c!	\ in direct buffer
    1 srp >srp-cmd-din-desc-cnt c!
;

: srp-prep-cmd-write ( addr len srplun -- )
    srp-prep-cmd-io
    10 srp >srp-cmd-buf-fmt c!	\ out direct buffer
    1 srp >srp-cmd-dout-desc-cnt c!
;

: srp-send-cmd ( -- )
    vscsi-debug? IF
        ." VSCSI: Sending SCSI cmd " srp >srp-cmd-cdb c@ . cr
    THEN
    srp srp-len srp-send-crq
;

: srp-rsp-find-sense ( -- addr len true | false )
    srp >srp-rsp-flags c@ SRP_RSP_FLAG_SNSVALID and 0= IF
        false EXIT
    THEN
    \ XXX FIXME: We assume the sense data is right at response
    \            data. A different server might actually have both
    \            some response data we need to skip *and* some sense
    \            data.
    srp >srp-rsp-data srp >srp-rsp-sense-len l@ true
;

\ Wait for a response to the last sent SRP command
\ returns a SCSI status code or -1 (HW error).
\
: srp-wait-rsp ( -- stat )
    srp-wait-crq not IF false EXIT THEN
    dup 1 <> IF
        ." VSCSI: Invalid CRQ response tag, want 1 got " . cr
	-1 EXIT
    THEN drop
    
    srp >srp-rsp-tag x@ dup 1 <> IF
        ." VSCSI: Invalid SRP response tag, want 1 got " . cr
	-1 EXIT
    THEN drop
    
    srp >srp-rsp-status c@
    vscsi-debug? IF
        ." VSCSI: Got response status: "
	dup .status-text cr
    THEN
;

\ -----------------------------------------------------------
\ Perform SCSI commands
\ -----------------------------------------------------------

8000000000000000 INSTANCE VALUE current-target

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
    \ Stash command addr & len
    >r >r				( buf-addr buf-len dir )
    \ Command has no data ?
    over 0= IF
        3drop current-target srp-prep-cmd-nodata
    ELSE
        \ Command is a read ?
        current-target swap IF srp-prep-cmd-read ELSE srp-prep-cmd-write THEN
    THEN
    \ Recover command and copy it to our srp buffer
    r> r>
    srp >srp-cmd-cdb swap move
    srp-send-cmd
    srp-wait-rsp

    \ Check for HW error
    dup -1 = IF
        0 0 rot EXIT
    THEN

    \ Other error status
    dup 0<> IF
       srp-rsp-find-sense IF
           vscsi-debug? IF
               over scsi-get-sense-data
               ." VSCSI: Sense key [ " dup . ." ] " .sense-text
	       ."  ASC,ASCQ: " . . cr
           THEN
       ELSE 0 0
           \ This relies on auto-sense from qemu... if that isn't always the
           \ case we should request sense here
           ." VSCSI: No sense data" cr
       THEN
       rot
    THEN
;

\ --------------------------------
\ Include the generic host helpers
\ --------------------------------

" scsi-host-helpers.fs" included

TRUE VALUE first-time-init?
0 VALUE open-count

\ Cleanup behind us
: vscsi-cleanup
    vscsi-debug? IF ." VSCSI: Cleaning up" cr THEN
    crq-cleanup

    \ Disable TCE bypass:
    vscsi-unit 0 rtas-set-tce-bypass
;

\ Initialize our vscsi instance
: vscsi-init ( -- true | false )
    vscsi-debug? IF ." VSCSI: Initializing" cr THEN

    my-unit to vscsi-unit

    \ Enable TCE bypass special qemu feature
    vscsi-unit 1 rtas-set-tce-bypass

    \ Initialize CRQ
    crq-init 0 <> IF false EXIT THEN

    \ Send init command
    " "(C0 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00)" drop
    crq-send not IF
        ." VSCSI: Error sending init command"
        crq-cleanup false EXIT
    THEN
 
    \ Wait reply
    crq-wait not IF
        crq-cleanup false EXIT
    THEN

    \ Check init reply
    crq c@ c0 <> crq 1 + c@ 02 <> or IF
        ." VSCSI: Initial handshake failed"
	crq-cleanup false EXIT
    THEN

    \ We should now login etc.. but we really don't need to
    \ with our qemu model

    \ Ensure we cleanup after booting
    first-time-init? IF
        ['] vscsi-cleanup add-quiesce-xt
	false to first-time-init?
    THEN

    true
;

: open
    vscsi-debug? IF ." VSCSI: Opening (count is " open-count . ." )" cr THEN

    open-count 0= IF
        vscsi-init IF
	    1 to open-count true
	ELSE ." VSCSI initialization failed !" cr false THEN
    ELSE
        open-count 1 + to open-count
        true
    THEN
;

: close
    vscsi-debug? IF ." VSCSI: Closing (count is " open-count . ." )" cr THEN

    open-count 0> IF
        open-count 1 - dup to open-count
	0= IF
	    vscsi-cleanup
	THEN
    THEN
;

\ -----------------------------------------------------------
\ SCSI scan at boot and child device support
\ -----------------------------------------------------------

\ We use SRP luns of the form 8000 | (bus << 8) | (id << 5) | lun
\ in the top 16 bits of the 64-bit LUN
: (set-target)
    to current-target
;

: dev-generate-srplun ( target lun -- )
    swap 8 << 8000 or or 30 <<
;

\ We obtain here a unit address on the stack, since our #address-cells
\ is 2, the 64-bit srplun is split in two cells that we need to join
\
\ Note: This diverges a bit from the original OF scsi spec as the two
\ cells are the 2 words of a 64-bit SRP LUN
: set-address ( srplun.lo srplun.hi -- )
    lxjoin (set-target)
;

\ We set max-transfer to a fixed value for now to avoid problems
\ with some CD-ROM drives.
\ FIXME: Check max transfer coming from VSCSI
: max-transfer ( -- n )
    10000 \ Larger value seem to have problems with some CDROMs
;

8 CONSTANT #dev
: dev-max-target ( -- #max-target )
    #dev
;

" scsi-probe-helpers.fs" included

\ Remove scsi functions from word list
scsi-close

: setup-alias
    " scsi" find-alias 0= IF
        " scsi" get-node node>path set-alias
    ELSE
        drop
    THEN 
;

: vscsi-init-and-scan  ( -- )
    \ Create instance for scanning:
    0 0 get-node open-node ?dup 0= IF EXIT THEN
    my-self >r
    dup to my-self
    \ Scan the VSCSI bus:
    scsi-find-disks
    setup-alias
    \ Close the temporary instance:
    close-node
    r> to my-self
;

: vscsi-add-disk
    " scsi-disk.fs" included
;

vscsi-add-disk
vscsi-init-and-scan
