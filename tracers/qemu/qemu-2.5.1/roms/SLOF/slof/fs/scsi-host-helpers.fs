\ This file is meant to be included by SCSI hosts to provide
\ helpers such as retry-scsi-command

\ Returns 1 for retry, 0 for return with no error and
\ -1 for return with an error
\
: check-retry-sense? ( sense-buf sense-len -- retry? )
    \ Check if the sense-len is at least 8 bytes
    8 < IF -1 EXIT THEN

    \ Fixed sense record, look for filemark etc...
    dup sense-data>response-code c@ 7e and 70 = IF
        dup sense-data>sense-key c@ e0 and IF drop -1 EXIT THEN
    THEN

    \ Get sense data
    scsi-get-sense-data? IF 	( ascq asc sense-key )
        \ No sense or recoverable, return success
	dup 2 < IF 3drop 0 EXIT THEN
	\ not ready and unit attention, retry
	dup 2 = swap 6 = or nip nip IF 1 EXIT THEN
    THEN
    \ Return failure
    -1
;

\ This is almost as the standard retry-command but returns
\ additionally the length of the returned sense information
\
\ The hw-err? field is gone, stat is -1 for a HW error, and
\ the sense data is provided iff stat is CHECK_CONDITION (02)
\
\ Additionally we wait 10ms between retries
\
0 INSTANCE VALUE rcmd-buf-addr
0 INSTANCE VALUE rcmd-buf-len
0 INSTANCE VALUE rcmd-dir
0 INSTANCE VALUE rcmd-cmd-addr
0 INSTANCE VALUE rcmd-cmd-len

: retry-scsi-command ( buf-addr buf-len dir cmd-addr cmd-len #retries -- ... )
                     ( ... 0 | [ sense-buf sense-len ] stat )
    >r \ stash #retries
    to rcmd-cmd-len to rcmd-cmd-addr to rcmd-dir to rcmd-buf-len to rcmd-buf-addr
    0  \ dummy status & sense
    r> \ retreive #retries              ( stat #retries )
    0 DO
        \ drop previous status & sense
        0<> IF 2drop THEN

	\ Restore arguments
	rcmd-buf-addr
	rcmd-buf-len
	rcmd-dir
	rcmd-cmd-addr
	rcmd-cmd-len

	\ Send command
	execute-scsi-command		( [ sense-buf sense-len ] stat )

	\ Success ?
	dup 0= IF LEAVE THEN

	\ HW error ?
	dup -1 = IF LEAVE THEN

	\ Check condition ?
	dup 2 = IF  			( sense-buf sense-len stat )
	    >r	\ stash stat		( sense-buf sense len )
	    2dup
	    check-retry-sense?	        ( sense-buf sense-len retry? )
	    r> swap \ unstash stat	( sense-buf sense-len stat retry? )
	    \ Check retry? result
	    CASE
	         0 OF 3drop 0 LEAVE ENDOF	\ Swallow error, return 0
	        -1 OF LEAVE ENDOF		\ No retry
	    ENDCASE
        ELSE \ Anything other than busy -> exit
            dup 8 <> IF LEAVE THEN
	THEN
	a ms
    LOOP
;

\ -----------------------------------------------------------
\ Some command helpers
\ -----------------------------------------------------------
\
\ TODO: Get rid of global "sector" and instead return an
\ allocated block for the caller to free

CREATE sector d# 512 allot
CREATE cdb 10 allot

: (inquiry) ( size -- buffer | NULL )
    dup cdb scsi-build-inquiry
    \ 16 retries for inquiry to flush out any UAs
    sector swap scsi-dir-read cdb scsi-param-size 10 retry-scsi-command
    \ Success ?
    0= IF sector ELSE 2drop 0 THEN
;

\ Read the initial 36bytes and then decide how much more is to be read
: inquiry ( -- buffer | NULL )
    d# 36 (inquiry) 0= IF 0 EXIT THEN
    sector inquiry-data>add-length c@ 5 +
    (inquiry)
;

: report-luns ( -- [ sector ] true | false )
    200 cdb scsi-build-report-luns
    \ 16 retries to flush out any UAs
    sector 200 scsi-dir-read cdb scsi-param-size 10 retry-scsi-command
    \ Success ?
    0= IF sector true ELSE drop false THEN
;

\ This routine creates a disk alias for the first found disk/cdrom
: make-disk-alias                               ( $name srplun -- )
    >r 2dup r> -rot                             ( $name srplun $name)
    find-alias 0<> IF 4drop exit THEN
    get-node node>path
    20 allot
    " /disk@" string-cat                        ( $name srplun npath npathl )
    rot base @ >r hex (u.) r> base ! string-cat ( $name $diskpath )
    set-alias
;
