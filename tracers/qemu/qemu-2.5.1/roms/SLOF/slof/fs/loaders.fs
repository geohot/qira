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

\ \\\\\\\\\\\\\\ Global Data
CREATE bootdevice 2 cells allot bootdevice 2 cells erase
CREATE bootargs 2 cells allot bootargs 2 cells erase
CREATE load-list 2 cells allot load-list 2 cells erase

: start-elf ( arg len entry -- )
   msr@ 7fffffffffffffff and 2000 or ciregs >srr1 ! call-client
;

: start-elf64 ( arg len entry r2 -- )
    msr@ 2000 or ciregs >srr1 !
    ciregs >r2  !
    call-client \ entry point is pointer to .opd
;

: set-bootpath
   s" disk" find-alias
   dup IF ELSE drop s" boot-device" evaluate find-alias THEN
   dup IF strdup ELSE 0 THEN
   encode-string s" bootpath" set-chosen
;

: set-netbootpath
   s" net" find-alias
   ?dup IF strdup encode-string s" bootpath" set-chosen THEN
;

: set-bootargs
   skipws 0 parse dup 0= IF
      2drop s" boot-file" evaluate
   THEN
   encode-string s" bootargs" set-chosen
;

: .(client-exec) ( arg len -- rc )
   s" snk" romfs-lookup 0<> IF
      \ Load SNK client 15 MiB after Paflof... FIXME: Hard-coded offset is ugly!
      paflof-start f00000 +
      elf-load-file-to-addr drop \ FIXME - check this for LE, currently its BE only
      dup @ swap 8 + @         \ populate entry r2
      start-elf64 client-data
   ELSE
      2drop false
   THEN
;
' .(client-exec) to (client-exec)

: .client-exec ( arg len -- rc ) set-bootargs (client-exec) ;
' .client-exec to client-exec

: netflash ( -- rc ) s" netflash 2000000 " (parse-line) $cat set-netbootpath
   client-exec
;

: netsave  ( "addr len {filename}[,params]" -- rc )
   (parse-line) dup 0> IF
      s" netsave " 2swap $cat set-netbootpath client-exec
   ELSE
      cr
      ." Usage: netsave addr len [bootp|dhcp,]filename[,siaddr][,ciaddr][,giaddr][,bootp-retries][,tftp-retries][,use_ci]"
      cr 2drop
   THEN
;

: ping  ( "{device-path:[device-args,]server-ip,[client-ip],[gateway-ip][,timeout]}" -- )
   my-self >r current-node @ >r  \ Save my-self
   (parse-line) open-dev dup  IF
      dup to my-self dup ihandle>phandle set-node
      dup
      s" ping" rot ['] $call-method CATCH  IF
         cr
         ." Not a pingable device"
         cr 3drop
      THEN
      swap close-dev
   ELSE
      cr
      ." Usage: ping device-path:[device-args,]server-ip,[client-ip],[gateway-ip][,timeout]"
      cr drop
   THEN
   r> set-node r> to my-self  \ Restore my-self
;
