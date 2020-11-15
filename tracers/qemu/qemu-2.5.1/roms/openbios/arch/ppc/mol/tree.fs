
: int-property ( val name -- )
	rot encode-int 2swap property
;


\ -------------------------------------------------------------
\ device-tree
\ -------------------------------------------------------------

" /" find-device

  " device-tree" device-name
	" bootrom" device-type

\ -------------------------------------------------------------
\ /memory
\ -------------------------------------------------------------

new-device
  " memory" device-name
	\ 12230 encode-int " reg" property
	external
	: open true ;
	: close ;
	\ claim ( phys size align -- base )
	\ release ( phys size -- )
finish-device

\ -------------------------------------------------------------
\ /mol/
\ -------------------------------------------------------------

new-device
	" mol" device-name
	1 " #address-cells" int-property
	0 " #size-cells" int-property

	external
	: open true ;
	: close ;

new-device
  " test" device-name

	external
  : open
		." /mol/test opened" cr
		" argument-str" " ipose" find-package drop interpose
		true
  ;
finish-device
finish-device

\ -------------------------------------------------------------
\ /cpus/
\ -------------------------------------------------------------

new-device
	" cpus" device-name
	1 " #address-cells" int-property
	0 " #size-cells" int-property

	external
	: open true ;
	: close ;
	: decode-unit parse-hex ;

finish-device

\ -------------------------------------------------------------
\ /packages
\ -------------------------------------------------------------

" /packages" find-device

	" packages" device-name
	external
	\ allow packages to be opened with open-dev
	: open true ;
	: close ;

\ /packages/mol-stdout
new-device
	" mol-stdout" device-name
	external
	: open true ;
	: close ;
	: write ( addr len -- actual )
		dup -rot type
	;
finish-device

\ XXXXXXXXXXXXXXXXXXXXXXX TESTING
" /" find-device
new-device
  " test" device-name
finish-device

\ -------------------------------------------------------------
\ The END
\ -------------------------------------------------------------
device-end
