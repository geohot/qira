\ tag: tftp support package
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

" /packages" find-device

\ 
\ IEEE 1275 obp-tftp package
\ 

new-device
  " obp-tftp" device-name
  \ now the methods...

finish-device

\ clean up afterwards
device-end
