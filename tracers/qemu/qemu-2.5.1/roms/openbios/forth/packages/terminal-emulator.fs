\ tag: terminal emulator support package
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

" /packages" find-device

\ 
\ IEEE 1275 terminal-emulator package
\ 

new-device
  " terminal-emulator" device-name
  \ now the methods...

finish-device

\ clean up afterwards

device-end
