\ *****************************************************************************
\ * Copyright (c) 2004, 2008 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

my-space pci-class-name type

my-space pci-device-generic-setup

pci-io-enable
pci-mem-enable

30 config-l@  pci-find-fcode execute-rom-fcode

: check-display ( nodepath len -- true|false ) \ true if display found and "screen" alias set
\ check if display available, set screen alias
2dup find-node \ ( path len phandle|0 ) find node
?dup IF
   \ node found, get "display-type" property
   s" display-type" rot get-property ( path len true|propaddr proplen 0 )
   0= IF
      ( path len propaddr proplen ) \ property found, check if the value is not "NONE"
      s" NONE" 0 char-cat ( path len propaddr proplen str strlen ) \ null-terminated NONE string
      str= 0= IF
         ( path len ) \ "display-type" property is not "NONE" so we can set "screen" alias
         s" screen" 2swap set-alias 
         true ( true ) \  return true
      ELSE
         2drop false ( false ) \ return false
      THEN
   THEN
THEN
;

get-node node>path s" /NVDA,DISPLAY-A" $cat check-display
0= IF
   \ no display found on DISPLAY-A ... check DISPLAY-B
   get-node node>path s" /NVDA,DISPLAY-B" $cat check-display
   drop \ drop result 
THEN

s" name" get-my-property drop s"  ( " type type s"  ) " type cr
