\ tag: /packages sub device tree
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

" /" find-device

new-device
  " packages" device-name
  : open true ;
  : close ;
finish-device

device-end
