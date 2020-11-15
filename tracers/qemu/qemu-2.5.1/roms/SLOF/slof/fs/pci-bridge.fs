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

\ get the PUID from the node above
get-node CONSTANT my-phandle
s" my-puid" my-phandle parent $call-static CONSTANT my-puid

\ Save the bus number provided by this bridge
pci-bus-number 1+ CONSTANT my-bus

s" pci-config-bridge.fs" included
s" dma-function.fs" included

\ generate the rom-fs filename from the vendor and device ID "pci-bridge_VENDORID_DEVICEID.fs"
: filename ( -- str len )
  s" pci-bridge_"
  my-space pci-vendor@ 4 int2str $cat
  s" _" $cat
  my-space pci-device@ 4 int2str $cat
  s" .fs" $cat
;

\ Set up the Bridge with either default or special settings
: setup ( -- )
        \ is there special handling for this device, given vendor and device id?
        filename romfs-lookup ?dup
                IF
                        \ give it a special treatment
                        evaluate
                ELSE
                        \ no special handling for this device, attempt autoconfiguration
                        my-space pci-class-name type 2a emit cr
                        my-space pci-bridge-generic-setup
                        my-space pci-reset-2nd
                THEN
;

\ Disable Bus Master, Memory Space and I/O Space for
\ this device and so for the scanning for the devices behind
pci-device-disable

\ Enalbe #PERR and #SERR reporting
pci-error-enable

\ Print out device information
my-space 42 pci-out     \ config-addr ascii('B')

\ and set up the bridge
setup

\ And enable Bus Master IO and MEM access again.
\ we need that on bridges so that the devices behind
\ can set their state on their own.
pci-master-enable
pci-mem-enable
pci-io-enable
