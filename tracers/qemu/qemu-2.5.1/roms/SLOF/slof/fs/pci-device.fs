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

get-node CONSTANT my-phandle

\ get the PUID from the node above
s" my-puid" my-phandle parent $call-static CONSTANT my-puid

\ define the config reads
: config-b@  puid >r my-puid TO puid my-space + rtas-config-b@ r> TO puid ;
: config-w@  puid >r my-puid TO puid my-space + rtas-config-w@ r> TO puid ;
: config-l@  puid >r my-puid TO puid my-space + rtas-config-l@ r> TO puid ;

\ define the config writes
: config-b!  puid >r my-puid TO puid my-space + rtas-config-b! r> TO puid ;
: config-w!  puid >r my-puid TO puid my-space + rtas-config-w! r> TO puid ;
: config-l!  puid >r my-puid TO puid my-space + rtas-config-l! r> TO puid ;

\ for Debug purposes: dumps the whole config space
: config-dump puid >r my-puid TO puid my-space pci-dump r> TO puid ;

\ prepare the device for subsequent use
\ this word should be overloaded by the device file (if present)
\ the device file can call this file before implementing
\ its own open functionality
: open
        puid >r             \ save the old puid
        my-puid TO puid     \ set up the puid to the devices Hostbridge
        pci-master-enable   \ And enable Bus Master, IO and MEM access again.
        pci-mem-enable      \ enable mem access
        pci-io-enable       \ enable io access
        r> TO puid          \ restore puid
        true
;

\ close the previously opened device
\ this word should be overloaded by the device file (if present)
\ the device file can call this file after its implementation
\ of own close functionality
: close 
        puid >r             \ save the old puid
        my-puid TO puid     \ set up the puid
        pci-device-disable  \ and disable the device
        r> TO puid          \ restore puid
;

s" dma-function.fs" included

\ generate the rom-fs filename from the vendor and device ID "pci-device_VENDORID_DEVICEID.fs"
: devicefile ( -- str len )
  s" pci-device_"
  my-space pci-vendor@ 4 int2str $cat
  s" _" $cat
  my-space pci-device@ 4 int2str $cat
  s" .fs" $cat
;

\ generate the rom-fs filename from the base-class id "pci-class_BASECLASS.fs"
: classfile ( -- str len )
  s" pci-class_"
  my-space pci-class@ 10 rshift 2 int2str $cat
  s" .fs" $cat
;

\ Set up the device with either default or special settings
: setup ( -- )
        \ is there special handling for this device, given vendor and device id?
        devicefile romfs-lookup ?dup
                IF
                        \ give it a special treatment
                        evaluate
                ELSE
                        classfile romfs-lookup ?dup
                        IF
                            \ give it a pci-class related treatment
                            evaluate
                        ELSE
                            \ no special handling for this device, attempt autoconfiguration
                            my-space pci-class-name type 2a emit cr
                            my-space pci-device-generic-setup
                        THEN
                THEN
;

\ Disable Bus Master, Memory Space and I/O Space for this device
\ if Bus Master function is needed it should be enabled/disabled by open/close in the device driver code
pci-device-disable

\ Enalbe #PERR and #SERR reporting
pci-error-enable

\ Print out device information
my-space 44 pci-out     \ config-addr ascii('D')

\ and set up the device
setup
