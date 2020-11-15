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

#include <rtas/rtas-init.fs>
#include <rtas/rtas-cpu.fs>
#include <rtas/rtas-reboot.fs>
#include <rtas/rtas-flash.fs>
#include <rtas/rtas-vpd.fs>

\ for update-flash
: (get-flashside)  ( -- flashside )  rtas-get-flashside  ;

' (get-flashside) to get-flashside

\ remember the current flashside
get-flashside to flashside? 

\ for update-flash
: (set-flashside)  ( flashside -- status )
   dup rtas-set-flashside =  IF  0  ELSE  -1  THEN
;

' (set-flashside) to set-flashside

: rtas-ibm-read-pci-config  ( size puid bus devfn off -- x )
   [ s" ibm,read-pci-config" rtas-get-token ] LITERAL rtas-cb rtas>token l!
   4 rtas-cb rtas>nargs l!
   2 rtas-cb rtas>nret l!
   swap 8 lshift or swap 10 lshift or rtas-cb rtas>args0 l!
   dup 20 rshift rtas-cb rtas>args1 l!
   ffffffff and rtas-cb rtas>args2 l!
   rtas-cb rtas>args3 l!
   enter-rtas
   rtas-cb rtas>args5 l@
;

: rtas-fetch-cpus  ( mask -- status )
   [ s" rtas-fetch-slaves" rtas-get-token ] LITERAL rtas-cb rtas>token l!
   1 rtas-cb rtas>nargs l!
   1 rtas-cb rtas>nret l!
   rtas-cb rtas>args0 l!
   0 rtas-cb rtas>args1 l!
   enter-rtas
   rtas-cb rtas>args1 l@
;

: rtas-stop-bootwatchdog  ( -- status )
   [ s" rtas-stop-bootwatchdog" rtas-get-token ] LITERAL rtas-cb rtas>token l!
   0 rtas-cb rtas>nargs l!
   1 rtas-cb rtas>nret l!
   enter-rtas
   rtas-cb rtas>args0 l@
;

: rtas-set-bootwatchdog  ( seconds -- )
   [ s" rtas-set-bootwatchdog" rtas-get-token ] LITERAL rtas-cb rtas>token l!
   1 rtas-cb rtas>nargs l!
   0 rtas-cb rtas>nret l!
   rtas-cb rtas>args0 l!
   enter-rtas
;

' rtas-set-bootwatchdog to set-watchdog

: rtas-dump-flash  ( offset cnt -- )
   [ s" rtas-dump-flash" rtas-get-token ] LITERAL rtas-cb rtas>token l!
   2 rtas-cb rtas>nargs l!
   0 rtas-cb rtas>nret l!
   rtas-cb rtas>args0 l!
   rtas-cb rtas>args1 l!
   enter-rtas
;

create blist 50 allot
blist 50 erase

: build-blocklist_old
   \ set version
   1 blist c!
   \ set length of block list
   50 blist 7 + c!
   \ no more block list
   0000000000000000 blist 8 + !
   \ first block
   get-load-base 0 + blist 10 + !
   80000 blist 18 + !
   get-load-base 80000 + blist 20 + !
   80000 blist 28 + !
   get-load-base 100000 + blist 30 + !
   80000 blist 38 + !
   get-load-base 180000 + blist 40 + !
   8006C blist 48 + !
;

80000 constant _block_size

: build-blocklist
   \ set length of block list
   \ length of flashfs at load-base is at offset 30... get it...
   get-load-base 30 + @
   \ calculate the number of blocks we need
   _block_size / 1 +
   \ total number of blocks is 2 (for header and block_list extension + (number of blocks for flashfs * 2 (1 for address 1 for length))
   2 * 2 + 8 * blist !
   \ set version ( in first byte only )
   1 blist c!
   \ no more block list
   0000000000000000 blist 8 + !
   \ length of flashfs at load-base is at offset 30... get it...
   get-load-base 30 + @
   \ i define one block to be 64K, so calculate the number of blocks we need and loop over them
   _block_size / 1 + 0 do
      get-load-base _block_size i * +  \ which position of load-base to store
      blist 10 +             \ at what offset of blist ( 0x8 + for header 0x8 + for extension )
      i 10 * +               \ for each loop we have done 0x10 +
      !                      \ store it
      get-load-base 30 + @
      _block_size i * -      \ remaining length
      dup _block_size > 
      IF                     \ is the remaining length > block size
	drop _block_size     \ then store the block size as length
      ELSE
			     \ do nothing (store remaining length)
      THEN
      blist 10 +          \ store the length at
      i 10 * +            \ correct blist offset 
      8 +                 \ + 8 (we have stored address, now the length)
      !                   \ store it
   loop
;



: build-blocklist-v0_old
   \ set version
   0 blist c!
   48 blist 7 + c!
   \ first block
   get-load-base 0 + blist 8 + !
   80000 blist 10 + !
   get-load-base 80000 + blist 18 + !
   80000 blist 20 + !
   get-load-base 100000 + blist 28 + !
   80000 blist 30 + !
   get-load-base 180000 + blist 38 + !
   8006C blist 40 + !
;

: build-blocklist-v0
   \ set length of block list
   \ length of flashfs at load-base is at offset 30... get it...
   get-load-base 30 + @
   \ calculate the number of blocks we need
   _block_size / 1 +
   \ total number of blocks is 1 (for header + (number of blocks for flashfs * 2 (1 for address 1 for length))
   2 * 1 + 8 * blist !
   \ length of flashfs at load-base is at offset 30... get it...
   get-load-base 30 + @
   \ i define one block to be 64K, so calculate the number of blocks we need and loop over them
   _block_size / 1 + 0 do
      get-load-base _block_size i * +  \ which position of load-base to store
      blist 8 +             \ at what offset of blist ( 0x8 + for header)
      i 10 * +               \ for each loop we have done 0x10 +
      !                      \ store it
      get-load-base 30 + @
      _block_size i * -      \ remaining length
      dup _block_size > 
      IF                     \ is the remaining length > block size
	drop _block_size     \ then store the block size as length
      ELSE
			     \ do nothing (store remaining length)
      THEN
      blist 8 +          \ store the length at
      i 10 * +            \ correct blist offset 
      8 +                 \ + 8 (we have stored address, now the length)
      !                   \ store it
   loop
;


: yy
   build-blocklist
   blist rtas-ibm-update-flash-64-and-reboot
;

: yy0
   build-blocklist-v0
   blist rtas-ibm-update-flash-64-and-reboot
;

: rtas-ibm-update-flash-64  ( block-list -- status )
   [ s" ibm,update-flash-64" rtas-get-token ] LITERAL rtas-cb rtas>token l!
   2 rtas-cb rtas>nargs l!
   1 rtas-cb rtas>nret l!
   rtas-cb rtas>args0 l!
   \ special unofficial parameter: if this is set to 1, the rtas function will not check, wether
   \ we are on the perm side... this is needed for "update-flash -c" to work...
   1 rtas-cb rtas>args1 l!
   enter-rtas
   rtas-cb rtas>args2 l@
;

\ for update-flash
: flash-write  ( image-address -- status)
   load-base-override >r to load-base-override build-blocklist-v0
   blist rtas-ibm-update-flash-64
   r> to load-base-override 0=  IF  true  ELSE  false  THEN
;

: commit  1 rtas-ibm-manage-flash-image ;
: reject  0 rtas-ibm-manage-flash-image ;

: rtas-ibm-validate-flash-image  ( image-to-commit -- status )
   [ s" ibm,validate-flash-image" rtas-get-token ] LITERAL rtas-cb rtas>token l!
   2 rtas-cb rtas>nargs l!
   2 rtas-cb rtas>nret l!
   rtas-cb rtas>args0 l!
   enter-rtas
   rtas-cb rtas>args1 l@
;

: rtas-get-blade-descr ( address size -- len status )
   [ s" rtas-get-blade-descr" rtas-get-token ] LITERAL rtas-cb rtas>token l!
   2 rtas-cb rtas>nargs l!
   2 rtas-cb rtas>nret l!
   rtas-cb rtas>args1 l!
   rtas-cb rtas>args0 l!
   enter-rtas
   rtas-cb rtas>args2 l@
   rtas-cb rtas>args3 l@
;
