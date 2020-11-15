\ *****************************************************************************
\ * Copyright (c) 2004, 2011 IBM Corporation
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
\ **************** PCI Helper functions  *******************
\ ----------------------------------------------------------

\ convert an integer to string of len digits
: int2str ( int len -- str len ) swap s>d rot <# 0 ?DO # LOOP #> ;

\ convert addr to busnr
: pci-addr2bus ( addr -- busnr ) 10 rshift FF and ;

\ convert addr to devnr
: pci-addr2dev ( addr -- dev ) B rshift 1F and ;

\ convert addr to functionnumber
: pci-addr2fn ( addr -- dev ) 8 rshift 7 and ;

\ convert busnr devnr to addr
: pci-bus2addr ( busnr devnr -- addr ) B lshift swap 10 lshift + ;

\ print out a pci config addr
: pci-addr-out ( addr -- ) dup pci-addr2bus 2 0.r space FFFF and 4 0.r ;

\ Dump out the whole configspace
: pci-dump ( addr -- )
        10 0 DO
                dup
                cr i 4 * +
                dup pci-addr-out space
                rtas-config-l@ 8 0.r
        LOOP
        drop cr
;


\ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
\ the following functions use l@ to fetch the data,
\ that's because the some pcie cores have probs with w@
\ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

\ read Vendor ID
: pci-vendor@ ( addr -- id )                 rtas-config-l@ FFFF and ;

\ read Device ID
: pci-device@ ( addr -- id )                 rtas-config-l@ 10 rshift ;

\ read Status
: pci-status@ ( addr -- status )         4 + rtas-config-l@ 10 rshift ;

\ read Revision ID
: pci-revision@ ( addr -- id )           8 + rtas-config-b@ ;

\ read Class Code
: pci-class@  ( addr -- class )          8 + rtas-config-l@ 8 rshift ;

\ read Cache Line Size
: pci-cache@  ( addr -- size )           C + rtas-config-b@ ;

\ read Header Type
: pci-htype@  ( addr -- type )           E + rtas-config-b@  ;

\ read Sub Vendor ID
: pci-sub-vendor@ ( addr -- sub-id )    2C + rtas-config-l@ FFFF and ;

\ read Sub Device ID
: pci-sub-device@ ( addr -- sub-id )    2C + rtas-config-l@ 10 rshift FFFF and ;

\ read Interrupt Pin
: pci-interrupt@  ( addr -- interrupt ) 3D + rtas-config-b@ ;

\ read Minimum Grant
: pci-min-grant@  ( addr -- min-gnt )   3E + rtas-config-b@ ;

\ read Maximum Latency
: pci-max-lat@  ( addr -- max-lat )     3F + rtas-config-b@ ;

\ Check if Capabilities are valid
: pci-capabilities?  ( addr -- 0|1 ) pci-status@ 4 rshift 1 and ;

\ fetch the offset of the next capability
: pci-cap-next  ( cap-addr -- next-cap-off ) rtas-config-b@ FC and ;

\ calc the address of the next capability
: pci-cap-next-addr  ( cap-addr -- next-cap-addr ) 1+ dup pci-cap-next dup IF swap -100 and + ELSE nip THEN ;


\ Dump out all capabilities
: pci-cap-dump ( addr -- )
        cr
        dup pci-capabilities? IF
                33 + BEGIN
                        pci-cap-next-addr dup 0<>
                WHILE
                        dup pci-addr-out s"  : " type
                        dup rtas-config-b@ 2 0.r cr
                REPEAT
                s" end found "
        ELSE
                s" capabilities not enabled!"
        THEN
        type cr drop
;

\ search the capability-list for this id
: pci-cap-find ( addr id -- capp-addr|0 )
        swap dup pci-capabilities? IF
                33 + BEGIN
                        pci-cap-next-addr dup 0<> IF
                                dup rtas-config-b@ 2 pick =
                        ELSE
                                true
                        THEN
                UNTIL
                nip
        ELSE
                2drop 0
        THEN
;

\ check wether this device is a pci-express device
: pci-express? ( addr -- 0|1 ) 10 pci-cap-find 0<> ;

\ check wether this device is a pci-express device
: pci-x? ( addr -- 0|1 ) 07 pci-cap-find 0<> ;

\ check wether this device has extended config space
: pci-config-ext? ( addr -- 0|1 ) pci-express? ;


\ Disable Bus Master, Memory Space and I/O Space for this device
: pci-device-disable ( -- ) my-space 4 + dup rtas-config-l@ 7 invert and swap rtas-config-l! ;

\ Enable Bus Master
: pci-master-enable ( -- ) my-space 4 + dup rtas-config-l@ 4 or swap rtas-config-l! ;

\ Disable Bus Master
: pci-master-disable ( -- ) my-space 4 + dup rtas-config-l@ 4 invert and swap rtas-config-l! ;

\ Enable response to mem accesses of pci device
: pci-mem-enable ( -- ) my-space 4 + dup rtas-config-w@ 2 or swap rtas-config-w! ;

\ Enable response to I/O accesses of pci-device
: pci-io-enable ( -- ) my-space 4 + dup rtas-config-w@ 1 or swap rtas-config-w! ;

\ Enable Bus Master, I/O and mem access
: pci-enable ( -- ) my-space 4 + dup rtas-config-w@ 7 or swap rtas-config-w! ;

\ Enable #PERR and #SERR errors of pci-device
: pci-error-enable ( -- ) my-space 4 + dup rtas-config-w@ 140 or swap rtas-config-w! ;

\ prints out the ScanInformation about a device
\ char is a sign for device type e.g. D - device ; B - bridge
: pci-out ( addr char -- )
        15 spaces
        over pci-addr-out
        s"  (" type emit s" ) : " type
        dup pci-vendor@ 4 0.r space
        pci-device@ 4 0.r
        4 spaces
;


\ set and fetch the interrupt Pin
: pci-irq-line@  ( addr -- irq-pin ) 3C + rtas-config-b@ ;
: pci-irq-line!  ( pin addr -- ) 3C + rtas-config-b! ;

\ set and fetch primary bus number
: pci-bus-prim! ( nr addr -- ) 18 + dup rtas-config-l@ FFFFFF00 and rot + swap rtas-config-l! ;
: pci-bus-prim@ ( addr -- nr ) 18 + rtas-config-l@ FF and ;

\ set and fetch secondary bus number
: pci-bus-scnd! ( nr addr -- ) 18 + dup rtas-config-l@ FFFF00FF and rot 8 lshift + swap rtas-config-l! ;
: pci-bus-scnd@ ( addr -- nr ) 18 + rtas-config-l@ 8 rshift FF and ;

\ set and fetch subordinate bus number
: pci-bus-subo! ( nr addr -- ) 18 + dup rtas-config-l@ FF00FFFF and rot 10 lshift + swap rtas-config-l! ;
: pci-bus-subo@ ( addr -- nr ) 18 + rtas-config-l@ 10 rshift FF and ;

\ set and fetch primary, secondary and subordinate bus number
: pci-bus! ( subo scnd prim addr -- ) swap rot 8 lshift + rot 10 lshift + swap 18 + dup rtas-config-l@ FF000000 and rot + swap rtas-config-l! ;
: pci-bus@ ( addr -- subo scnd prim ) 18 + rtas-config-l@ dup 10 rshift FF and swap dup 8 rshift FF and swap FF and ;

\ Reset secondary Status
: pci-reset-2nd ( addr -- ) 1C + dup rtas-config-l@ FFFF0000 or swap rtas-config-l! ;
