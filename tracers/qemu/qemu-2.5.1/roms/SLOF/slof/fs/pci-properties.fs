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

#include "pci-class-code-names.fs"

\ read the various bar type sizes
: pci-bar-size@     ( bar-addr -- bar-size ) -1 over rtas-config-l! rtas-config-l@ ;
: pci-bar-size-mem@ ( bar-addr -- mem-size ) pci-bar-size@ -10 and invert 1+ FFFFFFFF and ;
: pci-bar-size-io@  ( bar-addr -- io-size  ) pci-bar-size@ -4 and invert 1+ FFFFFFFF and ;

\ fetch raw bar size but keep original BAR value
: pci-bar-size ( bar-addr -- bar-size-raw )
        dup rtas-config-l@ swap \ fetch original Value  ( bval baddr )
        -1 over rtas-config-l!  \ make BAR show size    ( bval baddr )
        dup rtas-config-l@      \ and fetch the size    ( bval baddr bsize )
        -rot rtas-config-l!     \ restore Value
;

\ calc 32 bit MEM BAR size
: pci-bar-size-mem32 ( bar-addr -- bar-size )
        pci-bar-size            \ fetch raw size
        -10 and invert 1+       \ calc size
        FFFFFFFF and            \ keep lower 32 bits
;

\ calc 32 bit ROM BAR size
: pci-bar-size-rom ( bar-addr -- bar-size )
        pci-bar-size            \ fetch raw size
        FFFFF800 and invert 1+  \ calc size
        FFFFFFFF and            \ keep lower 32 bits
;

\ calc 64 bit MEM BAR size
: pci-bar-size-mem64 ( bar-addr -- bar-size )
        dup pci-bar-size        \ fetch raw size lower 32 bits
        swap 4 + pci-bar-size   \ fetch raw size upper 32 bits
        20 lshift +             \ and put them together
        -10 and invert 1+       \ calc size
;

\ calc IO BAR size
: pci-bar-size-io ( bar-addr -- bar-size )
        pci-bar-size            \ fetch raw size
        -4 and invert 1+        \ calc size
        FFFFFFFF and            \ keep lower 32 bits
;


\ decode the Bar Type
\ +----------------------------------------------------------------------------------------+
\ |                                         3 2 1 0                                        |
\ |           +----------------------------+-+--+-+                                        |
\ | MEM-BAR : |         Base Address       |P|TT|0|   P - prefechtable ; TT - 00 : 32 Bit  |
\ |           +----------------------------+-+--+-+                           10 : 64 Bit  |
\ |           +-------------------------------+-+-+                                        |
\ |  IO-BAR : |         Base Address          |0|1|                                        |
\ |           +-------------------------------+-+-+                                        |
\ | That is: 0 - no encoded BarType                                                        |
\ |          1 - IO - Bar                                                                  |
\ |          2 - Memory 32 Bit                                                             |
\ |          3 - Memory 32 Bit prefetchable                                                |
\ |          4 - Memory 64 Bit                                                             |
\ |          5 - Memory 64 Bit prefetchable                                                |
\ +----------------------------------------------------------------------------------------+
: pci-bar-code@ ( bar-addr -- 0|1..4|5 )
        rtas-config-l@ dup                \ fetch the BaseAddressRegister
        1 and IF                          \ IO BAR ?
                2 and IF 0 ELSE 1 THEN    \ only '01' is valid
        ELSE                              \ Memory BAR ?
                F and CASE
                        0   OF 2 ENDOF    \ Memory 32 Bit Non-Prefetchable
                        8   OF 3 ENDOF    \ Memory 32 Bit Prefetchable
                        4   OF 4 ENDOF    \ Memory 64 Bit Non-Prefetchable
                        C   OF 5 ENDOF    \ Memory 64 Bit Prefechtable
                        dup OF 0 ENDOF    \ Not a valid BarType
                ENDCASE
        THEN
;

\ ***************************************************************************************
\ Assigning the new Value to the BARs
\ ***************************************************************************************
\ align the current mem and set var to next mem
\ align with a size of 0 returns 0 !!!
: assign-var ( size var -- al-mem )
        2dup @                          \ ( size var size cur-mem ) read current free mem
        swap #aligned                   \ ( size var al-mem )       align the mem to the size
        dup 2swap -rot +                \ ( al-mem var new-mem )    add size to aligned mem
        swap !                          \ ( al-mem )                set variable to new mem
;

\ set bar to current free mem ( in variable ) and set variable to next free mem
: assign-bar-value32 ( bar size var -- 4 )
        over IF                         \ IF size > 0
                assign-var              \ | ( bar al-mem ) set variable to next mem
                swap rtas-config-l!     \ | ( -- )         set the bar to al-mem
        ELSE                            \ ELSE
                2drop drop              \ | clear stack
        THEN                            \ FI
        4                               \ size of the base-address-register
;

\ set bar to current free mem ( in variable ) and set variable to next free mem
: assign-bar-value64 ( bar size var -- 8 )
        over IF                         \ IF size > 0
                assign-var              \ | ( bar al-mem ) set variable to next mem
                swap                    \ | ( al-mem addr ) calc config-addr of this bar
                2dup rtas-config-l!     \ | ( al-mem addr ) set the Lower part of the bar to al-mem
                4 + swap 20 rshift      \ | ( al-mem>>32 addr ) prepare the upper part of the al-mem
                swap rtas-config-l!     \ | ( -- ) and set the upper part of the bar
        ELSE                            \ ELSE
                2drop drop              \ | clear stack
        THEN                            \ FI
        8                               \ size of the base-address-register
;

\ Setup a prefetchable 64bit BAR and return its size
: assign-mem64-bar ( bar-addr -- 8 )
        dup pci-bar-size-mem64         \ fetch size
        pci-next-mem64 @ 0 = IF          \ Check if we have 64-bit memory range
	    pci-next-mem
	ELSE
	    pci-next-mem64
	THEN
        assign-bar-value64              \ and set it all
;

\ Setup a prefetchable 32bit BAR and return its size
: assign-mem32-bar ( bar-addr -- 4 )
        dup pci-bar-size-mem32          \ fetch size
        pci-next-mem                    \ var to change
        assign-bar-value32              \ and set it all
;

\ Setup a non-prefetchable 64bit BAR and return its size
: assign-mmio64-bar ( bar-addr -- 8 )
        dup pci-bar-size-mem64          \ fetch size
        pci-next-mem64 @ 0 = IF          \ Check if we have 64-bit memory range
	    pci-next-mmio
	ELSE
	    pci-next-mem64              \ for board-qemu we will use same range
	THEN
        assign-bar-value64              \ and set it all
;

\ Setup a non-prefetchable 32bit BAR and return its size
: assign-mmio32-bar ( bar-addr -- 4 )
        dup pci-bar-size-mem32          \ fetch size
        pci-next-mmio                   \ var to change
        assign-bar-value32              \ and set it all
;

\ Setup an IO-Bar and return the size of the base-address-register
: assign-io-bar ( bar-addr -- 4 )
        dup pci-bar-size-io             \ fetch size
        pci-next-io                     \ var to change
        assign-bar-value32              \ and set it all
;

\ Setup an Expansion ROM bar
: assign-rom-bar ( bar-addr -- )
        dup pci-bar-size-rom            \ fetch size
        dup IF                          \ IF size > 0
                over >r                 \ | save bar addr for enable
                pci-next-mmio           \ | var to change
                assign-bar-value32      \ | and set it
                drop                    \ | forget the BAR length
                r@ rtas-config-l@       \ | fetch BAR
                1 or r> rtas-config-l!  \ | and enable the ROM
        ELSE                            \ ELSE
                2drop                   \ | clear stack
        THEN
;

\ Setup the BAR due to its type and return the size of the register (4 or 8 Bytes ) used as increment for the BAR-Loop
: assign-bar ( bar-addr -- reg-size )
        dup pci-bar-code@                       \ calc BAR type
        dup IF                                  \ IF >0
                CASE                            \ | CASE Setup the right type
                1 OF assign-io-bar     ENDOF    \ | - set up an IO-Bar
                2 OF assign-mmio32-bar ENDOF    \ | - set up an 32bit MMIO-Bar
                3 OF assign-mem32-bar  ENDOF    \ | - set up an 32bit MEM-Bar (prefetchable)
                4 OF assign-mmio64-bar ENDOF    \ | - set up an 64bit MMIO-Bar
                5 OF assign-mem64-bar  ENDOF    \ | - set up an 64bit MEM-Bar (prefetchable)
                ENDCASE                         \ | ESAC
        ELSE                                    \ ELSE
                ABORT                           \ | Throw an exception
        THEN                                    \ FI
;

\ Setup all the bars of a pci device
: assign-all-device-bars ( configaddr -- )
        28 10 DO                        \ BARs start at 10 and end at 27
                dup i +                 \ calc config-addr of the BAR
                assign-bar              \ and set it up
        +LOOP                           \ add 4 or 8 to the index and loop
        30 + assign-rom-bar             \ set up the ROM if available
;

\ Setup all the bars of a pci device
: assign-all-bridge-bars ( configaddr -- )
        18 10 DO                        \ BARs start at 10 and end at 17
                dup i +                 \ calc config-addr of the BAR
                assign-bar              \ and set it up
        +LOOP                           \ add 4 or 8 to the index and loop
        38 + assign-rom-bar             \ set up the ROM if available
;

\ +---------------------------------------------------------------------------------------+
\ | Numerical Representaton of a PCI address (PCI Bus Binding 2.2.1.1)                   |
\ |                                                                                       |
\ |           31      24       16    11   8        0                                      |
\ |           +--------+--------+-----+---+--------+                                      |
\ | phys.hi:  |npt000ss|  bus   | dev |fnc|   reg  |    n - 0 relocatable                 |
\ |           +--------+--------+-----+---+--------+    p - 1 prefetchable                |
\ |                                                     t - 1 aliased or <1MB or <64KB    |
\ |                                                    ss - 00 Configuration Space        |
\ |                                                         01 I/O Space                  |
\ |                                                         10 Memory Space 32bits        |
\ |                                                         11 Memory Space 64bits        |
\ +---------------------------------------------------------------------------------------+

\ ***************************************************************************************
\ Generating the assigned-addresses property
\ ***************************************************************************************
\ generate assigned-addresses property for 64Bit MEM-BAR and return BAR-reg-size
: gen-mem64-bar-prop ( prop-addr prop-len bar-addr -- prop-addr prop-len 8 )
        dup pci-bar-size-mem64                  \ fetch BAR Size        ( paddr plen baddr bsize )
        dup IF                                  \ IF Size > 0
                >r dup rtas-config-l@           \ | save size and fetch lower 32 bits ( paddr plen baddr val.lo R: size)
                over 4 + rtas-config-l@         \ | fetch upper 32 bits               ( paddr plen baddr val.lo val.hi R: size)
                20 lshift + -10 and >r          \ | calc 64 bit value and save it     ( paddr plen baddr R: size val )
                83000000 or encode-int+         \ | Encode config addr                ( paddr plen R: size val )
                r> encode-64+                   \ | Encode assigned addr              ( paddr plen R: size )
                r> encode-64+                   \ | Encode size                       ( paddr plen )
        ELSE                                    \ ELSE
                2drop                           \ | don't do anything
        THEN                                    \ FI
        8                                       \ sizeof(BAR) = 8 Bytes
;

\ generate assigned-addresses property for prefetchable 64Bit MEM-BAR and return BAR-reg-size
: gen-pmem64-bar-prop ( prop-addr prop-len bar-addr -- prop-addr prop-len 8 )
        dup pci-bar-size-mem64                  \ fetch BAR Size        ( paddr plen baddr bsize )
        dup IF                                  \ IF Size > 0
                >r dup rtas-config-l@           \ | save size and fetch lower 32 bits ( paddr plen baddr val.lo R: size)
                over 4 + rtas-config-l@         \ | fetch upper 32 bits               ( paddr plen baddr val.lo val.hi R: size)
                20 lshift + -10 and >r          \ | calc 64 bit value and save it     ( paddr plen baddr R: size val )
                C3000000 or encode-int+         \ | Encode config addr                ( paddr plen R: size val )
                r> encode-64+                   \ | Encode assigned addr              ( paddr plen R: size )
                r> encode-64+                   \ | Encode size                       ( paddr plen )
        ELSE                                    \ ELSE
                2drop                           \ | don't do anything
        THEN                                    \ FI
        8                                       \ sizeof(BAR) = 8 Bytes
;

\ generate assigned-addresses property for 32Bit MEM-BAR and return BAR-reg-size
: gen-mem32-bar-prop ( prop-addr prop-len bar-addr -- prop-addr prop-len 4 )
        dup pci-bar-size-mem32                  \ fetch BAR Size        ( paddr plen baddr bsize )
        dup IF                                  \ IF Size > 0
                >r dup rtas-config-l@           \ | save size and fetch value         ( paddr plen baddr val R: size)
                -10 and >r                      \ | calc 32 bit value and save it     ( paddr plen baddr R: size val )
                82000000 or encode-int+         \ | Encode config addr                ( paddr plen R: size val )
                r> encode-64+                   \ | Encode assigned addr              ( paddr plen R: size )
                r> encode-64+                   \ | Encode size                       ( paddr plen )
        ELSE                                    \ ELSE
                2drop                           \ | don't do anything
        THEN                                    \ FI
        4                                       \ sizeof(BAR) = 4 Bytes
;

\ generate assigned-addresses property for prefetchable 32Bit MEM-BAR and return BAR-reg-size
: gen-pmem32-bar-prop ( prop-addr prop-len bar-addr -- prop-addr prop-len 4 )
        dup pci-bar-size-mem32                  \ fetch BAR Size        ( paddr plen baddr bsize )
        dup IF                                  \ IF Size > 0
                >r dup rtas-config-l@           \ | save size and fetch value         ( paddr plen baddr val R: size)
                -10 and >r                      \ | calc 32 bit value and save it     ( paddr plen baddr R: size val )
                C2000000 or encode-int+         \ | Encode config addr                ( paddr plen R: size val )
                r> encode-64+                   \ | Encode assigned addr              ( paddr plen R: size )
                r> encode-64+                   \ | Encode size                       ( paddr plen )
        ELSE                                    \ ELSE
                2drop                           \ | don't do anything
        THEN                                    \ FI
        4                                       \ sizeof(BAR) = 4 Bytes
;

\ generate assigned-addresses property for IO-BAR and return BAR-reg-size
: gen-io-bar-prop ( prop-addr prop-len bar-addr -- prop-addr prop-len 4 )
        dup pci-bar-size-io                     \ fetch BAR Size                      ( paddr plen baddr bsize )
        dup IF                                  \ IF Size > 0
                >r dup rtas-config-l@           \ | save size and fetch value         ( paddr plen baddr val R: size)
                -4 and >r                       \ | calc 32 bit value and save it     ( paddr plen baddr R: size val )
                81000000 or encode-int+         \ | Encode config addr                ( paddr plen R: size val )
                r> encode-64+                   \ | Encode assigned addr              ( paddr plen R: size )
                r> encode-64+                   \ | Encode size                       ( paddr plen )
        ELSE                                    \ ELSE
                2drop                           \ | don't do anything
        THEN                                    \ FI
        4                                       \ sizeof(BAR) = 4 Bytes
;

\ generate assigned-addresses property for ROM-BAR
: gen-rom-bar-prop ( prop-addr prop-len bar-addr -- prop-addr prop-len )
        dup pci-bar-size-rom                    \ fetch BAR Size                      ( paddr plen baddr bsize )
        dup IF                                  \ IF Size > 0
                >r dup rtas-config-l@           \ | save size and fetch value         ( paddr plen baddr val R: size)
                FFFFF800 and >r                 \ | calc 32 bit value and save it     ( paddr plen baddr R: size val )
                82000000 or encode-int+         \ | Encode config addr                ( paddr plen R: size val )
                r> encode-64+                   \ | Encode assigned addr              ( paddr plen R: size )
                r> encode-64+                   \ | Encode size                       ( paddr plen )
        ELSE                                    \ ELSE
                2drop                           \ | don't do anything
        THEN                                    \ FI
;

\ add another BAR to the assigned addresses property and return the size of the encoded register
: pci-add-assigned-address ( prop-addr prop-len bar-addr -- prop-addr prop-len bsize )
        dup pci-bar-code@                               \ calc BAR type                         ( paddr plen baddr btype)
        CASE                                            \ CASE for the BAR types                ( paddr plen baddr )
                0 OF drop 4              ENDOF          \ - not a valid type so do nothing
                1 OF gen-io-bar-prop     ENDOF          \ - IO-BAR
                2 OF gen-mem32-bar-prop  ENDOF          \ - MEM32
                3 OF gen-pmem32-bar-prop ENDOF          \ - MEM32 prefetchable
                4 OF gen-mem64-bar-prop  ENDOF          \ - MEM64
                5 OF gen-pmem64-bar-prop ENDOF          \ - MEM64 prefetchable
        ENDCASE                                         \ ESAC ( paddr plen bsize )
;

\ generate the assigned address property for a PCI device
: pci-device-assigned-addresses-prop ( addr -- )
        encode-start                                    \ provide mem for property              ( addr paddr plen )
        2 pick 30 + gen-rom-bar-prop                    \ assign the rom bar
        28 10 DO                                        \ we have 6 possible BARs
                2 pick i +                              \ calc BAR address                      ( addr paddr plen bar-addr )      
                pci-add-assigned-address                \ and generate the props for the BAR
        +LOOP                                           \ increase Index by returned len
        s" assigned-addresses" property drop            \ and write it into the device tree
;

\ generate the assigned address property for a PCI bridge
: pci-bridge-assigned-addresses-prop ( addr -- )
        encode-start                                    \ provide mem for property
        2 pick 38 + gen-rom-bar-prop                    \ assign the rom bar
        18 10 DO                                        \ we have 2 possible BARs
                2 pick i +                              \ ( addr paddr plen current-addr )
                pci-add-assigned-address                \ and generate the props for the BAR
        +LOOP                                           \ increase Index by returned len
        s" assigned-addresses" property drop            \ and write it into the device tree
;

\ check if the range is valid and if so encode it into
\ child.hi child.mid child.lo parent.hi parent.mid parent.lo size.hi size.lo
\ This is needed to translate the childrens addresses
\ We implement only 1:1 mapping for all PCI bridges
: pci-bridge-gen-range ( paddr plen base limit type -- paddr plen )
        >r over -                       \ calc size             ( paddr plen base size R:type )
        dup 0< IF                       \ IF Size < 0           ( paddr plen base size R:type )
                2drop r> drop           \ | forget values       ( paddr plen )
        ELSE                            \ ELSE
                1+ swap 2swap           \ | adjust stack        ( size base paddr plen R:type )
                r@ encode-int+          \ | Child type          ( size base paddr plen R:type )
                2 pick encode-64+       \ | Child address       ( size base paddr plen R:type )
                r> encode-int+          \ | Parent type         ( size base paddr plen )
                rot encode-64+          \ | Parent address      ( size paddr plen )
                rot encode-64+          \ | Encode size         ( paddr plen )
        THEN                            \ FI
;


\ generate an mmio space to the ranges property
: pci-bridge-gen-mmio-range ( addr prop-addr prop-len -- addr prop-addr prop-len )
        2 pick 20 + rtas-config-l@      \ fetch Value           ( addr paddr plen val )
        dup 0000FFF0 and 10 lshift      \ calc base-address     ( addr paddr plen val base )
        swap 000FFFFF or                \ calc limit-address    ( addr paddr plen base limit )
        02000000 pci-bridge-gen-range   \ and generate it       ( addr paddr plen )
;

\ generate an mem space to the ranges property
: pci-bridge-gen-mem-range ( addr prop-addr prop-len -- addr prop-addr prop-len )
        2 pick 24 + rtas-config-l@      \ fetch Value           ( addr paddr plen val )
        dup 000FFFFF or                 \ calc limit Bits 31:0  ( addr paddr plen val limit.31:0 )
        swap 0000FFF0 and 10 lshift     \ calc base Bits 31:0   ( addr paddr plen limit.31:0 base.31:0 )
        4 pick 28 + rtas-config-l@      \ fetch upper Basebits  ( addr paddr plen limit.31:0 base.31:0 base.63:32 )
        20 lshift or swap               \ and calc Base         ( addr paddr plen base.63:0 limit.31:0 )
        4 pick 2C + rtas-config-l@      \ fetch upper Limitbits ( addr paddr plen base.63:0 limit.31:0 limit.63:32 )
        20 lshift or                    \ and calc Limit        ( addr paddr plen base.63:0 limit.63:0 )
        42000000 pci-bridge-gen-range   \ and generate it       ( addr paddr plen )
;

\ generate an io space to the ranges property
: pci-bridge-gen-io-range ( addr prop-addr prop-len -- addr prop-addr prop-len )
        2 pick 1C + rtas-config-l@      \ fetch Value           ( addr paddr plen val )
        dup 0000F000 and 00000FFF or    \ calc Limit Bits 15:0  ( addr paddr plen val limit.15:0 )
        swap 000000F0 and 8 lshift      \ calc Base Bits 15:0   ( addr paddr plen limit.15:0 base.15:0 )
        4 pick 30 + rtas-config-l@      \ fetch upper Bits      ( addr paddr plen limit.15:0 base.15:0 val )
        dup FFFF and 10 lshift rot or   \ calc Base             ( addr paddr plen limit.15:0 val base.31:0 )
        -rot FFFF0000 and or            \ calc Limit            ( addr paddr plen base.31:0 limit.31:0 )
        01000000 pci-bridge-gen-range   \ and generate it       ( addr paddr plen )
;

\ generate the ranges property for a PCI bridge
: pci-bridge-range-props ( addr -- )
        encode-start                    \ provide mem for property
        pci-bridge-gen-mmio-range       \ generate the non prefetchable Memory Entry
        pci-bridge-gen-mem-range        \ generate the prefetchable Memory Entry
        pci-bridge-gen-io-range         \ generate the IO Entry
        dup IF                          \ IF any space present (propsize>0)
                s" ranges" property     \ | write it into the device tree
        ELSE                            \ ELSE
               s" " s" ranges" property
                2drop                   \ | forget the properties
        THEN                            \ FI
        drop                            \ forget the address
;

\ create the interrupt map for this bridge
: pci-bridge-interrupt-map ( -- )
        encode-start                                    \ create the property                           ( paddr plen )
        get-node child                                  \ find the first child                          ( paddr plen handle )
        BEGIN dup WHILE                                 \ Loop as long as the handle is non-zero        ( paddr plen handle )
                dup >r >space                           \ Get the my-space                              ( paddr plen addr R: handle )
                pci-gen-irq-entry                       \ and Encode the interrupt settings             ( paddr plen R: handle)
                r> peer                                 \ Get neighbour                                 ( paddr plen handle )
        REPEAT                                          \ process next childe node                      ( paddr plen handle )
        drop                                            \ forget the null                               ( paddr plen )
        s" interrupt-map" property                      \ and set it                                    ( -- )
        1 encode-int s" #interrupt-cells" property      \ encode the cell#
        f800 encode-int 0 encode-int+ 0 encode-int+     \ encode the bit mask for config addr (Dev only)
        7 encode-int+ s" interrupt-map-mask" property   \ encode IRQ#=7 and generate property
;

\ ***************************************************************************************
\ Generating the reg property
\ ***************************************************************************************
\ reg = config-addr 0 0 0 0 [BAR-config-addr 0 0 size.high size.low]

\ encode the reg prop for a nonprefetchable 32bit MEM-BAR
: encode-mem32-bar ( prop-addr prop-len BAR-addr -- prop-addr prop-len 4 )
        dup pci-bar-size-mem32                  \ calc BAR-size ( not changing the BAR )
        dup IF                                  \ IF BAR-size > 0       ( paddr plen baddr bsize )
                >r 02000000 or encode-int+      \ | save size and encode BAR addr
                0 encode-64+                    \ | make mid and lo zero
                r> encode-64+                   \ | encode size
        ELSE                                    \ ELSE
                2drop                           \ | don't do anything
        THEN                                    \ FI
        4                                       \ BAR-Len = 4 (32Bit)
;

\ encode the reg prop for a prefetchable 32bit MEM-BAR
: encode-pmem32-bar ( prop-addr prop-len BAR-addr -- prop-addr prop-len 4 )
        dup pci-bar-size-mem32                  \ calc BAR-size ( not changing the BAR )
        dup IF                                  \ IF BAR-size > 0       ( paddr plen baddr bsize )
                >r 42000000 or encode-int+      \ | save size and encode BAR addr
                0 encode-64+                    \ | make mid and lo zero
                r> encode-64+                   \ | encode size
        ELSE                                    \ ELSE
                2drop                           \ | don't do anything
        THEN                                    \ FI
        4                                       \ BAR-Len = 4 (32Bit)
;

\ encode the reg prop for a nonprefetchable 64bit MEM-BAR
: encode-mem64-bar ( prop-addr prop-len BAR-addr -- prop-addr prop-len 8 )
        dup pci-bar-size-mem64                  \ calc BAR-size ( not changing the BAR )
        dup IF                                  \ IF BAR-size > 0       ( paddr plen baddr bsize )
                >r 03000000 or encode-int+      \ | save size and encode BAR addr
                0 encode-64+                    \ | make mid and lo zero
                r> encode-64+                   \ | encode size
        ELSE                                    \ ELSE
                2drop                           \ | don't do anything
        THEN                                    \ FI
        8                                       \ BAR-Len = 8 (64Bit)
;

\ encode the reg prop for a prefetchable 64bit MEM-BAR
: encode-pmem64-bar ( prop-addr prop-len BAR-addr -- prop-addr prop-len 8 )
        dup pci-bar-size-mem64                  \ calc BAR-size ( not changing the BAR )
        dup IF                                  \ IF BAR-size > 0       ( paddr plen baddr bsize )
                >r 43000000 or encode-int+      \ | save size and encode BAR addr
                0 encode-64+                    \ | make mid and lo zero
                r> encode-64+                   \ | encode size
        ELSE                                    \ ELSE
                2drop                           \ | don't do anything
        THEN                                    \ FI
        8                                       \ BAR-Len = 8 (64Bit)
;

\ encode the reg prop for a ROM-BAR
: encode-rom-bar ( prop-addr prop-len configaddr -- prop-addr prop-len )
        dup pci-bar-size-rom                            \ fetch raw BAR-size
        dup IF                                          \ IF BAR is used
                >r 02000000 or encode-int+              \ | save size and encode BAR addr
                0 encode-64+                            \ | make mid and lo zero
                r> encode-64+                           \ | calc and encode the size
        ELSE                                            \ ELSE
                2drop                                   \ | don't do anything
        THEN                                            \ FI
;

\ encode the reg prop for an IO-BAR
: encode-io-bar ( prop-addr prop-len BAR-addr BAR-value -- prop-addr prop-len 4 )
        dup pci-bar-size-io                     \ calc BAR-size ( not changing the BAR )
        dup IF                                  \ IF BAR-size > 0       ( paddr plen baddr bsize )
                >r 01000000 or encode-int+      \ | save size and encode BAR addr
                0 encode-64+                    \ | make mid and lo zero
                r> encode-64+                   \ | encode size
        ELSE                                    \ ELSE
                2drop                           \ | don't do anything
        THEN                                    \ FI
        4                                       \ BAR-Len = 4 (32Bit)
;

\ write the representation of this BAR into the reg property
: encode-bar ( prop-addr prop-len bar-addr -- prop-addr prop-len bar-len )
        dup pci-bar-code@                               \ calc BAR type
        CASE                                            \ CASE for the BAR types ( paddr plen baddr val )
                0 OF drop 4             ENDOF           \ - not a valid type so do nothing
                1 OF encode-io-bar      ENDOF           \ - IO-BAR
                2 OF encode-mem32-bar   ENDOF           \ - MEM32
                3 OF encode-pmem32-bar  ENDOF           \ - MEM32 prefetchable
                4 OF encode-mem64-bar   ENDOF           \ - MEM64
                5 OF encode-pmem64-bar  ENDOF           \ - MEM64 prefetchable
        ENDCASE                                         \ ESAC ( paddr plen blen )
;

\ Setup reg property
\ first encode the configuration space address
: pci-reg-props ( configaddr -- )
        dup encode-int                  \ configuration space           ( caddr paddr plen )
        0 encode-64+                    \ make the rest 0
        0 encode-64+                    \ encode the size as 0
        2 pick pci-htype@               \ fetch Header Type             ( caddr paddr plen type )
        1 and IF                        \ IF Bridge                     ( caddr paddr plen )
                18 10 DO                \ | loop over all BARs
                        2 pick i +      \ | calc bar-addr               ( caddr paddr plen baddr )
                        encode-bar      \ | encode this BAR             ( caddr paddr plen blen )
                     +LOOP              \ | increase LoopIndex by the BARlen
                2 pick 38 +             \ | calc ROM-BAR for a bridge   ( caddr paddr plen baddr )
                encode-rom-bar          \ | encode the ROM-BAR          ( caddr paddr plen )
        ELSE                            \ ELSE ordinary device          ( caddr paddr plen )
               28 10 DO                 \ | loop over all BARs
                        2 pick i +      \ | calc bar-addr               ( caddr paddr plen baddr )
                        encode-bar      \ | encode this BAR             ( caddr paddr plen blen )
                     +LOOP              \ | increase LoopIndex by the BARlen
                2 pick 30 +             \ | calc ROM-BAR for a device   ( caddr paddr plen baddr )
                encode-rom-bar          \ | encode the ROM-BAR          ( caddr paddr plen )
        THEN                            \ FI                            ( caddr paddr plen )
        s" reg" property                \ and store it into the property
        drop
;

\ ***************************************************************************************
\ Generating common properties
\ ***************************************************************************************
\ set up common properties for devices and bridges
: pci-common-props ( addr -- )
        dup pci-class-name device-name
        dup pci-vendor@    encode-int s" vendor-id"      property
        dup pci-device@    encode-int s" device-id"      property
        dup pci-revision@  encode-int s" revision-id"    property
        dup pci-class@     encode-int s" class-code"     property
                         3 encode-int s" #address-cells" property
                         2 encode-int s" #size-cells"    property

        dup pci-config-ext? IF 1 encode-int s" ibm,pci-config-space-type" property THEN

        dup pci-status@
                dup 9 rshift 3 and encode-int s" devsel-speed" property
                dup 7 rshift 1 and IF 0 0 s" fast-back-to-back" property THEN
                dup 6 rshift 1 and IF 0 0 s" 66mhz-capable" property THEN
                    5 rshift 1 and IF 0 0 s" udf-supported" property THEN
        dup pci-cache@     ?dup IF encode-int s" cache-line-size" property THEN
            pci-interrupt@ ?dup IF encode-int s" interrupts"      property THEN
;

\ set up device only properties
: pci-device-props ( addr -- )
        \ FIXME no s" compatible" prop
        \ FIXME no s" alternate-reg" prop
        \ FIXME no s" fcode-rom-offset" prop
        \ FIXME no s" power-consumption" prop
        dup pci-common-props
        dup pci-min-grant@ encode-int s" min-grant"   property
        dup pci-max-lat@   encode-int s" max-latency" property
        dup pci-sub-device@ ?dup IF encode-int s" subsystem-id" property THEN
        dup pci-sub-vendor@ ?dup IF encode-int s" subsystem-vendor-id" property THEN
        dup pci-device-assigned-addresses-prop
        pci-reg-props
        pci-hotplug-enabled IF
            \ QEMU uses static assignments for my-drc-index:
            \ 40000000h + $bus << 8 + $slot << 3
            dup dup pci-addr2bus 8 lshift
            swap pci-addr2dev 3 lshift or
            40000000 + encode-int s" ibm,my-drc-index" property
            \ QEMU uses "Slot $bus*32$slotno" for loc-code
            dup dup pci-addr2bus 20 *
            swap pci-addr2dev +
            a base !
            s" Slot " rot $cathex
            hex
            encode-string s" ibm,loc-code" property
        THEN
;

\ set up bridge only properties
: pci-bridge-props ( addr -- )
        \ FIXME no s" slot-names" prop
        \ FIXME no s" bus-master-capable" prop
        \ FIXME no s" clock-frequency" prop
        dup pci-bus@
              encode-int s" primary-bus" property
              encode-int s" secondary-bus" property
              encode-int s" subordinate-bus" property
        dup pci-bus@ drop encode-int rot encode-int+ s" bus-range" property
            pci-device-slots encode-int s" slot-names" property
        dup pci-bridge-range-props
        dup pci-bridge-assigned-addresses-prop
	\ Only create interrupt-map when it doesn't already exist
	\ (it can be provided by qemu)
	s" interrupt-map" get-node get-property IF
            pci-bridge-interrupt-map
	ELSE 2drop THEN
        pci-reg-props
;


\ used to set up all unknown Bridges.
\ If a Bridge has no special handling for setup
\ the device file (pci-bridge_VENDOR_DEVICE.fs) can call
\ this word to setup busses and scan beyond.
: pci-bridge-generic-setup ( addr -- )
        pci-device-slots >r             \ save the slot array on return stack
        dup pci-common-props            \ set the common properties before scanning the bus
        s" pci" device-type             \ the type is allways "pci"
        dup pci-bridge-probe            \ find all device connected to it
        dup assign-all-bridge-bars      \ set up all memory access BARs
        dup pci-set-irq-line            \ set the interrupt pin
        dup pci-set-capabilities        \ set up the capabilities
            pci-bridge-props            \ and generate all properties
        r> TO pci-device-slots          \ and reset the slot array
;

DEFER func-pci-device-props

\ used for an gerneric device set up
\ if a device has no special handling for setup
\ the device file (pci-device_VENDOR_DEVICE.fs) can call
\ this word to setup the device
: pci-device-generic-setup ( config-addr -- )
        dup assign-all-device-bars      \ calc all BARs
        dup pci-set-irq-line            \ set the interrupt pin
        dup pci-set-capabilities        \ set up the capabilities
        dup func-pci-device-props       \ and generate all properties
        drop                            \ forget the config-addr
;

' pci-device-props TO func-pci-device-props
