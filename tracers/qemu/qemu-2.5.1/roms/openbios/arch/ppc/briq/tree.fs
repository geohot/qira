\   briq specific initialization code
\ 
\   Copyright (C) 2004 Greg Watson
\ 
\   This program is free software; you can redistribute it and/or
\   modify it under the terms of the GNU General Public License
\   as published by the Free Software Foundation
\ 

\ -------------------------------------------------------------
\ device-tree
\ -------------------------------------------------------------

" /" find-device

" chrp" device-type
" TotalImpact,BRIQ-1" model
h# 80000000 encode-int " isa-io-base" property
1 encode-int " #interrupt-cells" property
1 encode-int " #size-cells" property

new-device
	" memory" device-name
	" memory" device-type
	0 encode-int h# 1E00000 encode-int encode+
	h# 2000000 encode-int encode+ h# 40000000 encode-int encode+ 
	  " available" property
	0 h# 40000000 reg
	external
	: open true ;
	: close ;
finish-device

new-device
	" cpu" device-name
	" cpu" device-type
	" " encode-string " translations" property
	0 encode-phys h# 8000000 encode-int encode+ " available" property
	d# 32 encode-int " d-cache-block-size" property
	8 encode-int " d-cache-sets" property
	d# 32768 encode-int " d-cache-size" property
	d# 32 encode-int " i-cache-block-size" property
	8 encode-int " i-cache-sets" property
	d# 32768 encode-int " i-cache-size" property
	" " encode-string " cache-unified" property
	2 encode-int " i-tlb-sets" property
	d# 128 encode-int " i-tlb-size" property
	2 encode-int " d-tlb-sets" property
	d# 128 encode-int " d-tlb-size" property
	" " encode-string " tlb-split" property
	2 encode-int " tlb-sets" property
	d# 256 encode-int " tlb-size" property
	" " encode-string " performance-monitor" property
	" " encode-string " graphics" property
	4 encode-int " reservation-granule-size" property
        d# 25000000 encode-int " timebase-frequency" property
        d# 300000000 encode-int " clock-frequency" property
        d# 66000000 encode-int " bus-frequency" property
        h# 88201 encode-int " cpu-version" property
	0 encode-int " reg" property
finish-device

" /pci" find-device
	h# 01000000 encode-int 0 encode-int encode+ 0 encode-int encode+
	  h# 80000000 encode-int encode+ 0 encode-int encode+ 
	  h# 01000000 encode-int encode+ 
	h# 02000000 encode-int encode+ 0 encode-int encode+ 0 encode-int encode+ 
	  h# C0000000 encode-int encode+ 0 encode-int encode+ 
	  h# 08000000 encode-int encode+ 
	" ranges" property
	" IBM,CPC710" model
	h# FF5F7700 encode-int " 8259-interrupt-acknowledge" property
	h# 0000F800 encode-int 0 encode-int encode+ 0 encode-int encode+ 
	  7 encode-int encode+
	  " interrupt-map-mask" property
	1 encode-int " #interrupt-cells" property
	h# 80000000 encode-int " system-dma-base" property
	d# 33333333 encode-int " clock-frequency" property
	" " encode-string " primary-bridge" property
	0 encode-int " pci-bridge-number" property
	h# FF500000 encode-int h# 100000 encode-int encode+ " reg" property
	0 encode-int 0 encode-int encode+ " bus-range" property

new-device
  " isa" device-name
  " isa" device-type
	2 encode-int " #address-cells" property
	1 encode-int " #size-cells" property

  external
  : open true ;
  : close ;

finish-device

: ?devalias ( alias-str alias-len device-str device-len --
  \		alias-str alias-len false | true )
  active-package >r
  " /aliases" find-device
  \ 2dup ." Checking " type
  2dup find-dev if     \ check if device exists
    drop
    2over find-dev if  \ do we already have an alias?
      \ ." alias exists" cr
      drop 2drop false
    else
      \ ." device exists" cr
      encode-string
      2swap property
      true
    then
  else
    \ ." device doesn't exist" cr
    2drop false
  then
  r> active-package!
  ;

:noname
  " hd"
  " /pci/pci-ata/ata-1/disk@0" ?devalias not if
    " /pci/pci-ata/ata-1/disk@1" ?devalias not if
      " /pci/pci-ata/ata-2/disk@0" ?devalias not if
        " /pci/pci-ata/ata-2/disk@1" ?devalias not if
	  2drop ." No disk found." cr
	then
      then
    then
  then

  " cdrom"
  " /pci/pci-ata/ata-1/cdrom@0" ?devalias not if
    " /pci/pci-ata/ata-1/cdrom@1" ?devalias not if
      " /pci/pci-ata/ata-2/cdrom@0" ?devalias not if
        " /pci/pci-ata/ata-2/cdrom@1" ?devalias not if
	  2drop ." No cdrom found" cr
	then
      then
    then
  then
; SYSTEM-initializer

new-device
	" ide" device-name
	" ide" device-type
	" WINBOND,82C553" model
	h# 28 encode-int " max-latency" property
	h# 2 encode-int " min-grant" property
	h# 1 encode-int " devsel-speed" property
	h# 0 encode-int " subsystem-vendor-id" property
	h# 0 encode-int " subsystem-id" property
	h# 1018A encode-int " class-code" property
	h# 5 encode-int " revision-id" property
	h# 105 encode-int " device-id" property
	h# 10AD encode-int " vendor-id" property
	h# 1003110 encode-int 0 encode-int encode+ h# 10020 encode-int encode+
	  h# 10 encode-int encode+ 0 encode-int encode+
	  h# 1003114 encode-int 0 encode-int encode+ h# 10030 encode-int encode+
	  h# 4 encode-int encode+ 0 encode-int encode+
	  h# 1003118 encode-int 0 encode-int encode+ h# 10040 encode-int encode+
	  h# 10 encode-int encode+ 0 encode-int encode+
	  h# 100311C encode-int 0 encode-int encode+ h# 10034 encode-int encode+
	  h# 4 encode-int encode+ 0 encode-int encode+
	  h# 1003120 encode-int 0 encode-int encode+ h# 10050 encode-int encode+
	  h# 10 encode-int encode+ 0 encode-int encode+
	  h# 1003124 encode-int 0 encode-int encode+ h# 10060 encode-int encode+
	  h# 10 encode-int encode+ 0 encode-int encode+
	  " assigned-addresses" property
	h# 3100 encode-int 0 encode-int encode+ 0 encode-int encode+
	  0 encode-int encode+ 0 encode-int encode+
	  h# 1003110 encode-int 0 encode-int encode+ h# 0 encode-int encode+
	  h# 10 encode-int encode+ 0 encode-int encode+
	  h# 1003114 encode-int 0 encode-int encode+ h# 0 encode-int encode+
	  h# 4 encode-int encode+ 0 encode-int encode+
	  h# 1003118 encode-int 0 encode-int encode+ h# 0 encode-int encode+
	  h# 10 encode-int encode+ 0 encode-int encode+
	  h# 100311C encode-int 0 encode-int encode+ h# 0 encode-int encode+
	  h# 4 encode-int encode+ 0 encode-int encode+
	  h# 1003120 encode-int 0 encode-int encode+ h# 0 encode-int encode+
	  h# 10 encode-int encode+ 0 encode-int encode+
	  h# 1003124 encode-int 0 encode-int encode+ h# 0 encode-int encode+
	  h# 10 encode-int encode+ 0 encode-int encode+
	  " reg" property
finish-device

new-device
	" ethernet" device-name
	" network" device-type
	" AMD,79C973" model
	h# 3800 encode-int 0 encode-int encode+ 0 encode-int encode+
	  0 encode-int encode+ 0 encode-int encode+
	  " reg" property
finish-device

" /pci/isa" find-device
	0 0 " assigned-addresses" property
	0 0 " ranges" property
	0 encode-int " slot-names" property
	d# 8333333 encode-int " clock-frequency" property
	0 encode-int " eisa-slots" property
	2 encode-int " #interrupt-cells" property
	" W83C553F" encode-string " compatible" property
	" WINBOND,82C553" model
	0 encode-int " max-latency" property
	0 encode-int " min-grant" property
	1 encode-int " devsel-speed" property
	0 encode-int " subsystem-vendor-id" property
	0 encode-int " subsystem-id" property
	h# 60100 encode-int " class-code" property
	h# 10 encode-int " revision-id" property
	h# 565 encode-int " device-id" property
	h# 10AD encode-int " vendor-id" property
	h# 3000 encode-int 0 encode-int encode+ 0 encode-int encode+
	  0 encode-int encode+ 0 encode-int encode+ " reg" property

new-device
	" rtc" device-name
	" rtc" device-type
	" DS17285S" model
	" MC146818" encode-string
	" DS17285S" encode-string encode+
	" pnpPNP,b00" encode-string encode+ " compatible" property
	8 encode-int 0 encode-int encode+ " interrupts" property
	h# 70 encode-int 1 encode-int encode+
	  2 encode-int encode+ " reg" property
finish-device

new-device
	" interrupt-controller" device-name
	" interrupt-controller" device-type
	" 8259" model
	" " encode-string " interrupt-controller" property
	2 encode-int " #interrupt-cells" property
	1 encode-int 
	2 encode-int encode+
	3 encode-int encode+
	6 encode-int encode+
	  " reserved-interrupts" property
	" 8259" encode-string
	  " chrp,iic" encode-string encode+ 
	  " compatible" property
	h# 20 encode-int 1 encode-int encode+
	  2 encode-int encode+ " reg" property
finish-device

new-device
	" serial" device-name
	" serial" device-type
	" no" encode-string " ctsrts" property
	" no" encode-string " xon" property
	" no" encode-string " parity" property
	d# 115200 encode-int " bps" property
	1 encode-int " stop-bits" property
	8 encode-int " data-bits" property
	h# 70800 encode-int " divisor" property
	h# 708000 encode-int " clock-frequency" property
	4 encode-int 0 encode-int encode+ " interrupts" property
	h# 3F8 encode-int 1 encode-int encode+
	  8 encode-int encode+ " reg" property
finish-device

" /pci" find-device
	" /pci/isa/interrupt-controller" find-dev if 
		encode-int " interrupt-parent" property 
	then
	h# 3800 encode-int 0 encode-int encode+ 
	  0 encode-int encode+ 1 encode-int encode+
	  " /pci/isa/interrupt-controller" find-dev if 
		encode-int encode+
	  then
	  h# 0C encode-int encode+ 1 encode-int encode+
	  " interrupt-map" property

" /pci/isa" find-device
	" /pci/isa/interrupt-controller" find-dev if 
		encode-int " interrupt-parent" property 
	then

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
