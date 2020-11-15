include config.fs

\ -------------------------------------------------------------------------
\ UPA encode/decode unit
\ -------------------------------------------------------------------------

: decode-unit-upa ( str len -- id lun )
  ascii , left-split
  ( addr-R len-R addr-L len-L )
  parse-hex
  -rot parse-hex
  swap
;

: encode-unit-upa ( id lun -- str len)
  swap
  pocket tohexstr
  " ," pocket tmpstrcat >r
  rot pocket tohexstr r> tmpstrcat drop
;

" /" find-device
  2 encode-int " #address-cells" property
  2 encode-int " #size-cells" property
  " sun4u" encode-string " compatible" property

  : encode-unit encode-unit-upa ;
  : decode-unit decode-unit-upa ;

new-device
  " memory" device-name
  " memory" device-type
  external
  : open true ;
  : close ;
  \ see arch/sparc64/lib.c for methods
finish-device

new-device
  " virtual-memory" device-name
  external
  \ see arch/sparc64/lib.c for methods
finish-device

" /options" find-device
  " disk" encode-string " boot-from" property

" /openprom" find-device
  " OBP 3.10.24 1999/01/01 01:01" encode-string " version" property
