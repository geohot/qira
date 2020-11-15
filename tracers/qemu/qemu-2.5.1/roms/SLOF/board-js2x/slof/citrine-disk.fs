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


( max-#blocks rsrc id -- )

new-device   

lwsplit swap wbsplit rot set-unit

s" disk" device-name  s" block" device-type

CONSTANT resource-id
CONSTANT max-#blocks
get-parent CONSTANT ppack


: our-disk-read ( lba count addr -- )
  >r >r >r resource-id r> r> r> s" do-read" ppack $call-static ;

0 pci-alias-disk

\ Requiered interface for deblocker

200   CONSTANT block-size
40000 CONSTANT max-transfer 

: read-blocks ( addr block# #blocks -- #read )
\   my-unit s" dev-read-blocks" $call-parent
   \ check if the read is within max-#blocks
   2dup + max-#blocks 1 + > IF 
     \ 2drop drop 0 \ return 0 
     \ returning 0 would be correct (maybe?) but it confuses the deblocker...
     \ so i erase whatever would have been read and return the "expected" #read
     dup >r 
     swap drop \ drop block# (not needed)
     block-size * erase \ erase at addr #blocks * block-size
     r>   \ return #read 
   ELSE
     dup >r rot our-disk-read r>
   THEN
;    

INSTANCE VARIABLE deblocker

: open ( -- okay? )
   0 0 s" deblocker" $open-package dup deblocker ! dup IF 
      s" disk-label" find-package IF
	 my-args rot interpose
      THEN
   THEN 0<> ;

: close ( -- )
   deblocker @ close-package ;

: seek ( pos.lo pos.hi -- status )
   2dup lxjoin max-#blocks 1 + block-size *  > IF 
     \ illegal seek, return -1
     2drop -1
   ELSE
     s" seek" deblocker @ $call-method
   THEN
;

: read ( addr len -- actual )
   s" read" deblocker @ $call-method ;


finish-device

