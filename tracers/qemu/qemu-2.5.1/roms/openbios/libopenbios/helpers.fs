\ tag: helper functions
\ 
\ deblocker / filesystem support
\ 
\ Copyright (C) 2003 Samuel Rydh
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 


\ create device node and any missing parents.
\ The new node becomes the active package

: create-node ( nodepath -- )
  recursive
  ascii / right-split
  2dup find-dev if
    active-package!
    2drop
  else
    ( nodename path )
    dup if
      create-node
    else
      device-tree @ active-package!
      2drop
    then
  then
  new-device
  device-name
  active-package
  finish-device
  active-package!
;
