\ This file is meant to be included by SCSI hosts to provide
\ probing helpers - scsi-find-disks

: wrapped-inquiry ( -- true | false )
    inquiry 0= IF false EXIT THEN
    \ Skip devices with PQ != 0
    sector inquiry-data>peripheral c@ e0 and 0 =
;

: scsi-read-lun     ( addr -- lun true | false )
    dup c@ C0 AND CASE
	40 OF w@-be 3FFF AND TRUE ENDOF
	0  OF w@-be          TRUE ENDOF
	dup dup OF ." Unsupported LUN format = " . cr FALSE ENDOF
    ENDCASE
;

: vscsi-report-luns ( -- array ndev )
    \ array of pointers, up to 8 devices
    dev-max-target 3 << alloc-mem dup
    0                                    ( devarray devcur ndev )
    dev-max-target 0 DO
	i 0 dev-generate-srplun (set-target)
	report-luns nip IF
	    sector l@                     ( devarray devcur ndev size )
	    sector 8 + swap               ( devarray devcur ndev lunarray size )
	    dup 8 + dup alloc-mem         ( devarray devcur ndev lunarray size size+ mem )
	    dup rot 0 fill                ( devarray devcur ndev lunarray size mem )
	    dup >r swap move r>           ( devarray devcur ndev mem )
	    dup sector l@ 3 >> 0 ?DO      ( devarray devcur ndev mem memcur )
		dup dup scsi-read-lun IF
		    j swap dev-generate-srplun  swap x! 8 +
		ELSE
		    2drop
		THEN
	    LOOP drop
	    rot                           ( devarray ndev mem devcur )
	    dup >r x! r> 8 +              ( devarray ndev devcur )
	    swap 1 +
	ELSE
	    dev-max-target 1 = IF
		\ Some USB MSC devices do not implement report
		\ luns. That will stall the bulk pipe. These devices are
		\ single lun devices, report it accordingly

		( devarray devcur ndev )
		16 alloc-mem ( devarray devcur ndev mem )
		dup 16 0 fill ( devarray devcur ndev mem )
		dup 0 0 dev-generate-srplun swap x!  ( devarray devcur ndev mem )
		rot x!  ( devarray ndev )
		1 +
		UNLOOP EXIT
	    THEN
	THEN
    LOOP
    nip
;

: make-media-alias ( $name srplun -- )
    >r
    get-next-alias ?dup IF
        r> make-disk-alias
    ELSE
        r> drop
    THEN
;

: scsi-find-disks      ( -- )
    ."        SCSI: Looking for devices" cr
    vscsi-report-luns
    0 ?DO
	dup x@
	BEGIN
	    dup x@
	    dup 0= IF drop TRUE ELSE
		(set-target) wrapped-inquiry IF
		    ."           " current-target (u.) type ."  "
		    \ XXX FIXME: Check top bits to ignore unsupported units
		    \            and maybe provide better printout & more cases
		    \ XXX FIXME: Actually check for LUNs
		    sector inquiry-data>peripheral c@ CASE
			0   OF ." DISK     : " " disk"  current-target make-media-alias ENDOF
			5   OF ." CD-ROM   : " " cdrom" current-target make-media-alias ENDOF
			7   OF ." OPTICAL  : " " cdrom" current-target make-media-alias ENDOF
			e   OF ." RED-BLOCK: " " disk"  current-target make-media-alias ENDOF
			dup dup OF ." ? (" . 8 emit 29 emit 5 spaces ENDOF
		    ENDCASE
		    sector .inquiry-text cr
		THEN
		8 + FALSE
	    THEN
	UNTIL drop
	8 +
    LOOP drop
;
