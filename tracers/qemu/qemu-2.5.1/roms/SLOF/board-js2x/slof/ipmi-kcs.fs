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


\ IPMI KCS interface to the BMC.

new-device
   ca8 1 set-unit

   : open true ;
   : close ;

   create descr-buf 100 allot

   : rtas-get-bmc-version ( -- adr len )
      descr-buf 100 rtas-get-blade-descr   ( len status )
      IF
         drop 0 0
      ELSE
         descr-buf 9 + swap 11 -               ( adr len )
      THEN
   ;

   ' rtas-get-bmc-version to bmc-version

   s" system-controller" 2dup device-name device-type
   \ s" IBM,BMC." get-build-name $cat encode-string s" model" property
   \ s" IBM,BMC.12345" encode-string s" model" property
   s" IBM,BMC." bmc-version $cat encode-string s" model" property
   0 0 s" ranges" property

   new-device

      : open true ;
      : close ;

      s" ipmi" 2dup device-name device-type
      s" ipmi-kcs" compatible

      1 encode-int ca8 encode-int+ 1 encode-int+ s" reg" property
      4 encode-int s" reg-spacing" property
      s" IBM,BMC." bmc-version $cat encode-string s" model" property

      s" ipmi"  get-node node>path set-alias

   finish-device

finish-device
