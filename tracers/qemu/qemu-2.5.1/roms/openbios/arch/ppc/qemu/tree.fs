\   QEMU specific initialization code
\
\   This program is free software; you can redistribute it and/or
\   modify it under the terms of the GNU General Public License
\   as published by the Free Software Foundation
\

include config.fs

\ -------------------------------------------------------------
\ device-tree
\ -------------------------------------------------------------

" /" find-device
\ Apple calls the root node device-tree
" device-tree" device-name
[IFDEF] CONFIG_PPC64 2 [ELSE] 1 [THEN] encode-int " #address-cells" property
1 encode-int " #size-cells" property
h# 05f5e100 encode-int " clock-frequency" property

new-device
	" cpus" device-name
	1 encode-int " #address-cells" property
	0 encode-int " #size-cells" property
	external

	: encode-unit ( unit -- str len )
		pocket tohexstr
	;

	: decode-unit ( str len -- unit )
		parse-hex
	;

finish-device

new-device
	" memory" device-name
	" memory" device-type
	external
	: open true ;
	: close ;
finish-device

new-device
	" rom" device-name
	h# ff800000 encode-int 0 encode-int encode+ " reg" property
	1 encode-int " #address-cells" property
	h# ff800000 encode-int h# 800000 encode-int encode+
	h# ff800000 encode-int encode+ " ranges" property
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

\ /packages/terminal-emulator
new-device
	" terminal-emulator" device-name
	external
	: open true ;
	: close ;
	\ : write ( addr len -- actual )
	\	dup -rot type
	\ ;
finish-device

\ -------------------------------------------------------------
\ The END
\ -------------------------------------------------------------
device-end
