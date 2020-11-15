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

\ PAPR PCI host bridge.

0 VALUE phb-debug?


." Populating " pwd cr

\ needed to find the right path in the device tree
: decode-unit ( addr len -- phys.lo ... phys.hi )
   2 hex-decode-unit       \ decode string
   b lshift swap           \ shift the devicenumber to the right spot
   8 lshift or             \ add the functionnumber
   \ my-bus 10 lshift or   \ add the busnumber (assume always bus 0)
   0 0 rot                 \ make phys.lo = 0 = phys.mid
;

\ needed to have the right unit address in the device tree listing
\ phys.lo=phys.mid=0 , phys.hi=config-address
: encode-unit ( phys.lo phys-mid phys.hi -- unit-str unit-len )
   nip nip                     \ forget the phys.lo and phys.mid
   dup 8 rshift 7 and swap     \ calculate function number
   B rshift 1F and             \ calculate device number
   over IF 2 ELSE nip 1 THEN   \ create string with dev#,fn# or dev# only?
   hex-encode-unit
;


0 VALUE my-puid

: setup-puid
  s" reg" get-node get-property 0= IF
    decode-64 to my-puid 2drop
  THEN
;

setup-puid

: config-b@  puid >r my-puid TO puid rtas-config-b@ r> TO puid ;
: config-w@  puid >r my-puid TO puid rtas-config-w@ r> TO puid ;
: config-l@  puid >r my-puid TO puid rtas-config-l@ r> TO puid ;

\ define the config writes
: config-b!  puid >r my-puid TO puid rtas-config-b! r> TO puid ;
: config-w!  puid >r my-puid TO puid rtas-config-w! r> TO puid ;
: config-l!  puid >r my-puid TO puid rtas-config-l! r> TO puid ;


: map-in ( phys.lo phys.mid phys.hi size -- virt )
   phb-debug? IF cr ." map-in called: " .s cr THEN
   \ Ignore the size, phys.lo and phys.mid, get BAR from config space
   drop nip nip                         ( phys.hi )
   \ Sanity check whether config address is in expected range:
   dup FF AND dup 10 28 WITHIN NOT swap 30 <> AND IF
      cr ." phys.hi = " . cr
      ABORT" map-in with illegal config space address"
   THEN
   00FFFFFF AND                         \ Need only bus-dev-fn+register bits
   dup config-l@                        ( phys.hi' bar.lo )
   dup 7 AND 4 = IF                     \ Is it a 64-bit BAR?
      swap 4 + config-l@ lxjoin         \ Add upper part of 64-bit BAR
   ELSE
      nip
   THEN
   F NOT AND                            \ Clear indicator bits
   translate-my-address
   phb-debug? IF ." map-in done: " .s cr THEN
;

: map-out ( virt size -- )
   phb-debug? IF ." map-out called: " .s cr THEN
   2drop 
;


: dma-alloc ( size -- virt )
   phb-debug? IF cr ." dma-alloc called: " .s cr THEN
   fff + fff not and                  \ Align size to next 4k boundary
   alloc-mem
   \ alloc-mem always returns aligned memory - double check just to be sure
   dup fff and IF
      ." Warning: dma-alloc got unaligned memory!" cr
   THEN
;

: dma-free ( virt size -- )
   phb-debug? IF cr ." dma-free called: " .s cr THEN
   fff + fff not and                  \ Align size to next 4k boundary
   free-mem
;


\ Helper variables for dma-map-in and dma-map-out
0 VALUE dma-window-liobn        \ Logical I/O bus number
0 VALUE dma-window-base         \ Start address of window
0 VALUE dma-window-size         \ Size of the window

0 VALUE bm-handle               \ Bitmap allocator handle
0 VALUE my-virt
0 VALUE my-size
0 VALUE dev-addr
0 VALUE tmp-dev-addr

\ Read helper variables (LIOBN, DMA window base and size) from the
\ "ibm,dma-window" property. This property can be either located
\ in the PCI device node or in the bus node, so we've got to use the
\ "calling-child" variable here to get to the node that initiated the call.
\ XXX We should search all the way up the tree to the PHB ...
: (init-dma-window-vars)  ( -- )
\   ." Foo called in " pwd cr
\   ." calling child is " calling-child .node cr
\   ." parent is " calling-child parent .node cr
   s" ibm,dma-window" calling-child get-property IF
       s" ibm,dma-window" calling-child parent get-property 
       ABORT" no dma-window property available"
   THEN
   decode-int TO dma-window-liobn
   decode-64 TO dma-window-base
   decode-64 TO dma-window-size
   2drop
   bm-handle 0= IF
       dma-window-base dma-window-size 1000 bm-allocator-init to bm-handle
       \ Sometimes the window-base appears as zero, that does not
       \ go well with NULL pointers. So block this address
       dma-window-base 0= IF
          bm-handle 1000 bm-alloc drop
       THEN
   THEN
;

: (clear-dma-window-vars)  ( -- )
    0 TO dma-window-liobn
    0 TO dma-window-base
    0 TO dma-window-size
;

\ We assume that firmware never maps more than the whole dma-window-size
\ so we cheat by calculating the remainder of addr/windowsize instead
\ of taking care to maintain a list of assigned device addresses
: dma-virt2dev  ( virt -- devaddr )
   dma-window-size mod dma-window-base +
;

: dma-map-in  ( virt size cachable? -- devaddr )
   phb-debug? IF cr ." dma-map-in called: " .s cr THEN
   (init-dma-window-vars)
   drop                               ( virt size )

   to my-size
   to my-virt
   bm-handle my-size bm-alloc
   to dev-addr
   dev-addr 0 < IF
       ." Bitmap allocation Failed " dev-addr .
       FALSE EXIT
   THEN
   dev-addr to tmp-dev-addr

   my-virt my-size
   bounds dup >r                      ( v+s virt  R: virt )
   swap fff + fff not and             \ Align end to next 4k boundary
   swap fff not and                   ( v+s' virt'  R: virt )
   ?DO
       \ ." mapping " i . cr
       dma-window-liobn                \ liobn
       tmp-dev-addr                    \ ioba
       i 3 OR                          \ Make a read- & writeable TCE
       ( liobn ioba tce  R: virt )
       hv-put-tce ABORT" H_PUT_TCE failed"
       tmp-dev-addr 1000 + to tmp-dev-addr
   1000 +LOOP
   r> drop
   my-virt FFF and dev-addr or
   (clear-dma-window-vars)
;

: dma-map-out  ( virt devaddr size -- )
   phb-debug? IF cr ." dma-map-out called: " .s cr THEN
   (init-dma-window-vars)
   to my-size
   to dev-addr
   to my-virt
   dev-addr fff not and to dev-addr
   dev-addr to tmp-dev-addr

   my-virt my-size                    ( virt size )
   bounds                             ( v+s virt )
   swap fff + fff not and             \ Align end to next 4k boundary
   swap fff not and                   ( v+s' virt' )
   ?DO
       \ ." unmapping " i . cr
       dma-window-liobn                \ liobn
       tmp-dev-addr                    \ ioba
       i                               \ Lowest bits not set => invalid TCE
       ( liobn ioba tce )
       hv-put-tce ABORT" H_PUT_TCE failed"
       tmp-dev-addr 1000 + to tmp-dev-addr
   1000 +LOOP
   bm-handle dev-addr my-size bm-free
   (clear-dma-window-vars)
;

: dma-sync  ( virt devaddr size -- )
   phb-debug? IF cr ." dma-sync called: " .s cr THEN
   \ TODO: Call flush-cache or sync here?
   3drop
;


: open  true ;
: close ;

\ Parse the "ranges" property of the root pci node to decode the available
\ memory ranges. See "PCI Bus Binding to IEEE Std 1275-1994" for details.
\ The memory ranges are then used for setting up the device bars (if necessary)
: phb-parse-ranges ( -- )
   \ First clear everything, in case there is something missing in the ranges
   0  pci-next-io !
   0  pci-max-io !
   0  pci-next-mem !
   0  pci-max-mem !
   0  pci-next-mmio !
   0  pci-max-mmio !
   0  pci-next-mem64 !
   0  pci-max-mem64 !

   \ Now get the "ranges" property
   s" ranges" get-node get-property 0<> ABORT" ranges property not found"
   ( prop-addr prop-len )
   BEGIN
      dup
   WHILE
      decode-int                      \ Decode phys.hi
      3000000 AND                     \ Filter out address space in phys.hi
      CASE
         1000000 OF                             \ I/O space?
            decode-64 dup >r pci-next-io !      \ Decode PCI base address
            decode-64 drop                      \ Forget the parent address
            decode-64 r> + pci-max-io !         \ Decode size & calc max address
            pci-next-io @ 0= IF
               pci-next-io @ 10 + pci-next-io ! \ BARs must not be set to zero
            THEN
         ENDOF
         2000000 OF                             \ 32-bit memory space?
            decode-64 pci-next-mem !            \ Decode mem base address
            decode-64 drop                      \ Forget the parent address
            decode-64 2 / dup >r                \ Decode and calc size/2
            pci-next-mem @ + dup pci-max-mem !  \ and calc max mem address
            dup pci-next-mmio !                 \ which is the same as MMIO base
            r> + pci-max-mmio !                 \ calc max MMIO address
         ENDOF
         3000000 OF                             \ 64-bit memory space?
	    decode-64 pci-next-mem64 !
	    decode-64 drop                      \ Forget the parent address
	    decode-64 pci-max-mem64 !
         ENDOF
      ENDCASE
   REPEAT
   ( prop-addr prop-len )
   2drop

   phb-debug? IF
     ." pci-next-io   = " pci-next-io @ . cr
     ." pci-max-io    = " pci-max-io  @ . cr
     ." pci-next-mem  = " pci-next-mem @ . cr
     ." pci-max-mem   = " pci-max-mem  @ . cr
     ." pci-next-mmio = " pci-next-mmio @ . cr
     ." pci-max-mmio  = " pci-max-mmio @ . cr
     ." pci-next-mem64  = " pci-next-mem64 @ . cr
     ." pci-max-mem64   = " pci-max-mem64  @ . cr
   THEN
;

: phb-pci-walk-bridge ( -- )
    phb-debug? IF ."   Calling pci-walk-bridge " pwd cr THEN

    get-node child ?dup 0= IF EXIT THEN    \ get and check if we have children
    0 to pci-device-slots                  \ reset slot array to unpoppulated
    BEGIN
        dup                                \ Continue as long as there are children
    WHILE
        dup set-node                       \ Set child node as current node
        my-space pci-set-slot              \ set the slot bit
        my-space pci-htype@                \ read HEADER-Type
        7f and                             \ Mask bit 7 - multifunction device
        CASE
            0 OF my-space pci-device-setup ENDOF  \ | set up the device
            1 OF my-space pci-bridge-setup ENDOF  \ | set up the bridge
            dup OF my-space pci-htype@ pci-out ENDOF
        ENDCASE
        peer
    REPEAT drop
    get-parent set-node
;

\ Landing routing to probe the popuated device tree
: phb-pci-probe-bus ( busnr -- )
    drop phb-pci-walk-bridge
;

\ Stub routine, as qemu has enumerated, we already have the device
\ properties set.
: phb-pci-device-props ( addr -- )
    dup pci-class-name device-name
    dup pci-device-assigned-addresses-prop
    drop
;

\ Scan the child nodes of the pci root node to assign bars, fixup
\ properties etc.
: phb-setup-children
   puid >r                          \ Save old value of puid
   my-puid TO puid                  \ Set current puid
   phb-parse-ranges
   1 TO pci-hotplug-enabled
   s" qemu,phb-enumerated" get-node get-property 0<> IF
       1 0 (probe-pci-host-bridge)
   ELSE
       2drop
       ['] phb-pci-probe-bus TO func-pci-probe-bus
       ['] phb-pci-device-props TO func-pci-device-props
       phb-pci-walk-bridge          \ PHB device tree is already populated.
   THEN
   r> TO puid                       \ Restore previous puid
;
phb-setup-children
