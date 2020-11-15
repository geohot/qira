\ tag: Device Tree
\ 
\ this code implements IEEE 1275-1994 ch. 3.5
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 


\ root node
new-device
  " OpenBiosTeam,OpenBIOS" device-name
  1 encode-int " #address-cells" property
  : open true ;
  : close ;
  : decode-unit parse-hex ;
  : encode-unit ( addr -- str len )
    pocket tohexstr
  ;

new-device
  " aliases" device-name
  : open true ;
  : close ;
finish-device
  
new-device
  " openprom" device-name
  " BootROM"  device-type
  " OpenFirmware 3" model
  0 0 " relative-addressing"  property
  0 0 " supports-bootinfo"    property
  1 encode-int " boot-syntax" property
  
  : selftest
    ." OpenBIOS selftest... succeded" cr
    true
  ;
  : open true ;
  : close ;

finish-device
  
new-device
  " options" device-name
finish-device

new-device
  " chosen" device-name
  0 encode-int " stdin" property
  0 encode-int " stdout" property
  \ " hda1:/boot/vmunix" encode-string " bootpath" property
  \ " -as" encode-string " bootargs" property
finish-device
  
\ END
finish-device
