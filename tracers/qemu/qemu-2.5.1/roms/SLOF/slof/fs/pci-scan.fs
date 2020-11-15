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

\ ----------------------------------------------------------
\ **********  Variables to be set by host bridge  **********
\ ----------------------------------------------------------

\ Values of the next free memory area
VARIABLE pci-next-mem           \ prefetchable memory mapped
VARIABLE pci-max-mem
VARIABLE pci-next-mmio          \ non-prefetchable memory
VARIABLE pci-max-mmio
VARIABLE pci-next-io            \ I/O space
VARIABLE pci-max-io
VARIABLE pci-next-mem64           \ prefetchable 64-bit memory mapped
VARIABLE pci-max-mem64

\ Counter of busses found
0 VALUE pci-bus-number
\ Counter of devices found
0 VALUE pci-device-number
\ bit field of devices plugged into this bridge
0 VALUE pci-device-slots
\ byte field holding the device-slot number vector of the current device
\ the vector can be as deep as the max depth of bridges possible
\ 3,4,5 means
\       the 5th slot on the bus of the bridge in
\       the 4th slot on the bus of the bridge in
\       the 3rd slot on the HostBridge bus
here 100 allot CONSTANT pci-device-vec
0 VALUE pci-device-vec-len
\ enable/disable creation of hotplug-specific properties
0 VALUE pci-hotplug-enabled


\ Fixme Glue to the pci-devices ... remove this later
: next-pci-mem ( addr -- addr ) pci-next-mem ;
: next-pci-mmio ( addr -- addr ) pci-next-mmio ;
: next-pci-io ( addr -- addr ) pci-next-io ;


#include "pci-helper.fs"

\ Dump out the pci device-slot vector
: pci-vec ( -- )
        cr s" device-vec(" type
        pci-device-vec-len dup 2 0.r s" ):" type
        1+ 0 DO
                pci-device-vec i + c@
                space 2 0.r
        LOOP
        cr
;

\ prints out all relevant pci variables
: pci-var-out ( -- )
        s"   mem:" type pci-next-mem @ 16 0.r cr
        s"  mmio:" type pci-next-mmio @ 16 0.r cr
        s"    io:" type pci-next-io @ 16 0.r cr
;


\ Update the device-slot number vector
\ Set the bit of the DeviceSlot in the Slot array
: pci-set-slot ( addr -- )
        pci-addr2dev dup                \ calc slot number
        pci-device-vec-len              \ the end of the vector
        pci-device-vec + c!             \ and update the vector
        80000000 swap rshift            \ calc bit position of the device slot
        pci-device-slots or             \ set this bit
        TO pci-device-slots             \ and write it back
;

\ Update pci-next-mmio to be 1MB aligned and set the mmio-base register
\ and set the Limit register to the maximum available address space
\ needed for scanning possible devices behind the bridge
: pci-bridge-set-mmio-base ( addr -- )
        pci-next-mmio @ 100000 #aligned         \ read the current Value and align to 1MB boundary
        dup 100000 + pci-next-mmio !            \ and write back with 1MB for bridge
        10 rshift                               \ mmio-base reg is only the upper 16 bits
        pci-max-mmio @ 1- FFFF0000 and or       \ and Insert mmio Limit (set it to max)
        swap 20 + rtas-config-l!                \ and write it into the bridge
;

\ Update pci-next-mmio to be 1MB aligned and set the mmio-limit register
\ The Limit Value is one less then the upper boundary
\ If the limit is less than the base the mmio is disabled
: pci-bridge-set-mmio-limit ( addr -- )
        pci-next-mmio @ 100000 #aligned         \ fetch current value and align to 1MB
        dup pci-next-mmio !                     \ and write it back
        1- FFFF0000 and                         \ make it one less and keep upper 16 bits
        over 20 + rtas-config-l@ 0000FFFF and   \ fetch original value
        or swap 20 + rtas-config-l!             \ and write it into the Reg
;

\ Update pci-next-mem to be 1MB aligned and set the mem-base and mem-base-upper register
\ and set the Limit register to the maximum available address space
\ needed for scanning possible devices behind the bridge
: pci-bridge-set-mem-base ( addr -- )
        pci-next-mem @ 100000 #aligned          \ read the current Value and align to 1MB boundary
        dup 100000 + pci-next-mem !             \ and write back with 1MB for bridge
        over 24 + rtas-config-w@                \ check if 64bit support
        1 and IF                                \ IF 64 bit support
                pci-next-mem64 @ 100000000 #aligned \ | read the current Value of 64-bit and align to 4GB boundary
                dup 100000000 + pci-next-mem64 x!   \ | and write back with 1GB for bridge
                2 pick swap                         \ |
                20 rshift                           \ | keep upper 32 bits
                swap 28 + rtas-config-l!            \ | and write it into the Base-Upper32-bits
                pci-max-mem64 @ 20 rshift           \ | fetch max Limit address and keep upper 32 bits
                2 pick 2C + rtas-config-l!          \ | and set the Limit
        THEN                                    \ FI
        10 rshift                               \ keep upper 16 bits
        pci-max-mem @ 1- FFFF0000 and or        \ and Insert mmem Limit (set it to max)
        swap 24 + rtas-config-l!                \ and write it into the bridge
;

\ Update pci-next-mem to be 1MB aligned and set the mem-limit register
\ The Limit Value is one less then the upper boundary
\ If the limit is less than the base the mem is disabled
: pci-bridge-set-mem-limit ( addr -- )
        pci-next-mem @ 100000 #aligned          \ read the current Value and align to 1MB boundary
        dup pci-next-mem !                      \ and write it back
        1-                                      \ make limit one less than boundary
        over 24 + rtas-config-w@                \ check if 64bit support
        1 and IF                                \ IF 64 bit support
                pci-next-mem64 @ 100000000 #aligned \ | Reat current value of 64-bar and align at 4GB
                dup pci-next-mem64 x!               \ | and write it back
                1-                                  \ | make limite one less than boundary
                2 pick swap                         \ |
                20 rshift                           \ | keep upper 32 bits
                swap 2C + rtas-config-l!            \ | and write it into the Limit-Upper32-bits
        THEN                                    \ FI
        FFFF0000 and                            \ keep upper 16 bits
        over 24 + rtas-config-l@ 0000FFFF and   \ fetch original Value
        or swap 24 + rtas-config-l!             \ and write it into the bridge
;

\ Update pci-next-io to be 4KB aligned and set the io-base and io-base-upper register
\ and set the Limit register to the maximum available address space
\ needed for scanning possible devices behind the bridge
: pci-bridge-set-io-base ( addr -- )
        pci-next-io @ 1000 #aligned             \ read the current Value and align to 4KB boundary
        dup 1000 + pci-next-io !                \ and write back with 4K for bridge
        over 1C + rtas-config-l@                \ check if 32bit support
        1 and IF                                \ IF 32 bit support
                2dup 10 rshift                  \ | keep upper 16 bits
                pci-max-io @ FFFF0000 and or    \ | insert upper 16 bits of Max-Limit
                swap 30 + rtas-config-l!        \ | and write it into the Base-Upper16-bits
        THEN                                    \ FI
        8 rshift 000000FF and                   \ keep upper 8 bits
        pci-max-io @ 1- 0000FF00 and or         \ insert upper 8 bits of Max-Limit
        over rtas-config-l@ FFFF0000 and        \ fetch original Value
        or swap 1C + rtas-config-l!             \ and write it into the bridge
;

\ Update pci-next-io to be 4KB aligned and set the io-limit register
\ The Limit Value is one less then the upper boundary
\ If the limit is less than the base the io is disabled
: pci-bridge-set-io-limit ( addr -- )
        pci-next-io @ 1000 #aligned             \ read the current Value and align to 4KB boundary
        dup pci-next-io !                       \ and write it back
        1-                                      \ make limit one less than boundary
        over 1D + rtas-config-b@                \ check if 32bit support
        1 and IF                                \ IF 32 bit support
                2dup FFFF0000 and               \ | keep upper 16 bits
                over 30 + rtas-config-l@        \ | fetch original Value
                or swap 30 + rtas-config-l!     \ | and write it into the Limit-Upper16-bits
        THEN                                    \ FI
        0000FF00 and                            \ keep upper 8 bits
        over 1C + rtas-config-l@ FFFF00FF and   \ fetch original Value
        or swap 1C + rtas-config-l!             \ and write it into the bridge
;

\ set up all base registers to the current variable Values
: pci-bridge-set-bases ( addr -- )
        dup pci-bridge-set-mmio-base
        dup pci-bridge-set-mem-base
            pci-bridge-set-io-base
;

\ set up all limit registers to the current variable Values
: pci-bridge-set-limits ( addr -- )
        dup pci-bridge-set-mmio-limit
        dup pci-bridge-set-mem-limit
            pci-bridge-set-io-limit
;

\ ----------------------------------------------------------
\ ******************  PCI Scan functions  ******************
\ ----------------------------------------------------------

\ define function pointer as forward declaration of pci-probe-bus
DEFER func-pci-probe-bus
DEFER func-pci-bridge-range-props

\ Setup the Base and Limits in the Bridge
\ and scan the bus(es) beyond that Bridge
: pci-bridge-probe ( addr -- )
        dup pci-bridge-set-bases                        \ SetUp all Base Registers
	dup func-pci-bridge-range-props                 \ Setup temporary "range
        pci-bus-number 1+ TO pci-bus-number             \ increase number of busses found
        pci-device-vec-len 1+ TO pci-device-vec-len     \ increase the device-slot vector depth
        dup                                             \ stack config-addr for pci-bus!
        FF swap                                         \ Subordinate Bus Number ( for now to max to open all subbusses )
        pci-bus-number swap                             \ Secondary   Bus Number ( the new busnumber )
        dup pci-addr2bus swap                           \ Primary     Bus Number ( the current bus )
        pci-bus!                                        \ and set them into the bridge
        pci-enable                                      \ enable mem/IO transactions
        dup pci-bus-scnd@ func-pci-probe-bus            \ and probe the secondary bus
        dup pci-bus-number swap pci-bus-subo!           \ set SubOrdinate Bus Number to current number of busses
        pci-device-vec-len 1- TO pci-device-vec-len     \ decrease the device-slot vector depth
        dup pci-bridge-set-limits                       \ SetUp all Limit Registers
        drop                                            \ forget the config-addr
;

\ set up the pci-device
: pci-device-setup ( addr -- )
        drop                            \ since the config-addr is coded in my-space, drop it here
        s" pci-device.fs" included      \ and setup the device as node in the device tree
;

\ set up the pci bridge
: pci-bridge-setup ( addr -- )
        drop                            \ since the config-addr is coded in my-space, drop it here
        s" pci-bridge.fs" included      \ and setup the bridge as node in the device tree
;

\ add the new found device/bridge to the device tree and set it up
: pci-add-device ( addr -- )
        new-device                      \ create a new device-tree node
            dup set-space               \ set the config addr for this device tree entry
            dup pci-set-slot            \ set the slot bit
            dup pci-htype@              \ read HEADER-Type
            7f and                      \ Mask bit 7 - multifunction device
            CASE
               0 OF pci-device-setup ENDOF  \ | set up the device
               1 OF pci-bridge-setup ENDOF  \ | set up the bridge
               dup OF dup pci-htype@ pci-out ENDOF
           ENDCASE
        finish-device                   \ and close the device-tree node
;

\ check for multifunction and for each function
\ (dependig from header type) call device or bridge setup
: pci-setup-device ( addr -- )
        dup pci-htype@                      \ read HEADER-Type
        80 and IF 8 ELSE 1 THEN             \ check for multifunction
        0 DO                                \ LOOP over all possible functions (either 8 or only 1)
                dup
                i 8 lshift +                \ calc device-function-config-addr
                dup pci-vendor@             \ check if valid function
                FFFF = IF
                        drop                \ non-valid so forget the address
                ELSE
                    pci-device-number 1+    \ increase the number of devices
                    TO pci-device-number    \ and store it
                    pci-add-device          \ and add the device to the device tree and set it up
                THEN
        LOOP                                \ next function
        drop                                \ forget the device-addr
;

\ check if a device is plugged into this bus at this device number
: pci-probe-device ( busnr devicenr -- )
        pci-bus2addr                                    \ calc pci-address
        dup pci-vendor@                                 \ fetch Vendor-ID
        FFFF = IF                                       \ check if valid
                drop                                    \ if not forget it
        ELSE
                pci-setup-device                        \ if valid setup the device
        THEN
;

\ walk through all 32 possible pci devices on this bus and probe them
: pci-probe-bus ( busnr -- )
        0 TO pci-device-slots           \ reset slot array to unpoppulated
        20 0 DO
                dup
                i pci-probe-device
        LOOP
        drop
;

\ setup the function pointer used in pci-bridge-setup
' pci-probe-bus TO func-pci-probe-bus

\ ----------------------------------------------------------
\ ******************  System functions  ********************
\ ----------------------------------------------------------
\ Setup the whole system for pci devices
\ start with the bus-min and try all busses
\ until at least 1 device was found
\ ( needed for HostBridges that don't start with Bus 0 )
: pci-probe-all ( bus-max bus-min -- )                  \ Check all busses from bus-min up to bus-max if needed
        0 TO pci-device-vec-len                         \ reset the device-slot vector
        DO
                i TO pci-bus-number                     \ set current Busnumber
                0 TO pci-device-number                  \ reset Device Number
                pci-bus-number pci-probe-bus            \ and probe this bus
                pci-device-number 0 > IF LEAVE THEN     \ if we found a device we're done
        LOOP                                            \ else next bus
;

: (probe-pci-host-bridge) ( bus-max bus-min -- )
        0d emit ."  Adapters on " puid 10 0.r cr        \ print the puid we're looking at
        ( bus-max bus-min ) pci-probe-all               \ and walk the bus
        pci-device-number 0= IF                         \ IF no devices found
                15 spaces                               \ | indent the output
                ." None" cr                             \ | tell the world our result
        THEN                                            \ FI
;

\ probe the hostbridge that is specified in my-puid
\ for the mmio mem and io addresses:
\ base is the least available address
\ max is the highest available address
: probe-pci-host-bridge ( bus-max bus-min mmio-max mmio-base mem-max mem-base io-max io-base my-puid -- )
        puid >r TO puid                                 \ save puid and set the new
        pci-next-io !                                   \ save the next io-base address
        pci-max-io !                                    \ save the max io-space address
        pci-next-mem !                                  \ save the next mem-base address
        pci-max-mem !                                   \ save the max mem-space address
        pci-next-mmio !                                 \ save the next mmio-base address
        pci-max-mmio !                                  \ save the max mmio-space address
	(probe-pci-host-bridge)
        r> TO  puid                                     \ restore puid
;

\ provide the device-alias definition words
#include <pci-aliases.fs>

\ provide all words for the interrupts settings
#include <pci-interrupts.fs>

\ provide all words for the pci capabilities init
#include <pci-capabilities.fs>

\ provide all words needed to generate the properties and/or assign BAR values
#include "pci-properties.fs"

\ setup the function pointer for bridge ranges
' pci-bridge-range-props TO func-pci-bridge-range-props
