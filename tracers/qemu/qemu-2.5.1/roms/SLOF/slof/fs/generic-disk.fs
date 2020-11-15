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


\ Generic disk support

\ Input:
\        name of device ( e.g. "disk", "cdrom", ... )
\        dev# 

\ Needs from parent in device tree:
\        dev-read-blocks ( addr block# #blocks phys.lo ... phys.hi -- #read )
\        block-size
\        max-transfer

\ Provides:
\        open ( -- okay? )
\        close ( -- )
\        read ( addr len -- actual )
\        seek ( pos.lo pos.hi -- status )
\        read-blocks ( addr block# #blocks -- #read )
\ Uses:
\        disk-label package interpose for partition and file systems support
\        deblocker package for byte read support

( str len phys.lo ... phys.hi -- )
new-device set-unit                                          ( str len )
  2dup device-name 
  s" 0 pci-alias-" 2swap $cat evaluate
  s" block" device-type      

\ Requiered interface for deblocker

   s" block-size" $call-parent   CONSTANT block-size
   s" max-transfer" $call-parent CONSTANT max-transfer 

: read-blocks ( addr block# #blocks -- #read )
   my-unit s" dev-read-blocks" $call-parent
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
   s" seek" deblocker @ $call-method ;

: read ( addr len -- actual )
   s" read" deblocker @ $call-method ;

finish-device
