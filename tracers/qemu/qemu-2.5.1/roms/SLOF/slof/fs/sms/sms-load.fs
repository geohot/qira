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

false VALUE (sms-loaded?)

false value (sms-available?)

s" sms.fs" romfs-lookup IF true to (sms-available?) drop THEN

(sms-available?) [IF]

#include "packages/sms.fs"

\ Initialize SMS NVRAM handling.
#include "sms-nvram.fs"

\ Dynamically load sms code from the romfs file
\ Assumption is that skeleton sms package already exists
\ but aside of open & close, all other methods are in a romfs file (sms.fs)
\ Here we open the package and load the rest of the functionality

\ After that, one needs to find-device and execute sms-start method
\ The shorthand for that is given as (global) sms-start word

: $sms-node s" /packages/sms" ;

: (sms-init-package) ( -- true|false )
   (sms-loaded?) ?dup IF EXIT THEN
   $sms-node ['] find-device catch IF 2drop false EXIT THEN
   s" sms.fs" [COMPILE] included
   device-end
   true dup to (sms-loaded?)
;

\ External wrapper for sms package method
: (sms-evaluate) ( addr len -- )
   (sms-init-package) not IF
      cr ." SMS is not available." cr 2drop exit
   THEN

   s" Entering SMS ..." type
   disable-watchdog
   reset-dual-emit

   \ if we only had execute-device-method...
   2>r $sms-node find-device
   2r> evaluate
   device-end
   vpd-boot-import
;

: sms-start ( -- ) s" sms-start" (sms-evaluate) ;
: sms-fru-replacement ( -- ) s" sms-fru-replacement" (sms-evaluate) ;

[ELSE]

: sms-start ( -- ) cr ." SMS is not available." cr ;
: sms-fru-replacement ( -- ) cr ." SMS FRU replacement is not available." cr ;

[THEN]

