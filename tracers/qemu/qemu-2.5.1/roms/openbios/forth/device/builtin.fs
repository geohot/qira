\ tag: builtin devices
\ 
\ this code implements IEEE 1275-1994 
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

\ nodes it's children:

" /" find-device
  
new-device
  " builtin" device-name
  : open true ;
  : close ;

new-device
  " console" device-name
  : open true ;
  : close ;
  : write dup >r bounds ?do i c@ (emit) loop r> ;
  : read dup >r bounds ?do (key) i c! loop r> ;
finish-device

\ clean up afterwards
finish-device
0 active-package!
