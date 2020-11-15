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

\ Generic config space access function - xt is execution token of rtas-config-xx
: config-xt  ( config-addr xt -- data )
   puid >r                            \ Safe puid
   my-puid TO puid                    \ Set my-puid
   swap dup ffff00 AND 0= IF          \ Has bus-device-function been specified?
      my-space OR                     \ No: use my-space instead
   THEN
   swap execute                       \ Execute the rtas-config-xx function
   r> TO puid                         \ Restore previous puid
;

\ define the config reads
: config-b@  ( config-addr -- data )  ['] rtas-config-b@ config-xt ;
: config-w@  ( config-addr -- data )  ['] rtas-config-w@ config-xt ;
: config-l@  ( config-addr -- data )  ['] rtas-config-l@ config-xt ;

\ define the config writes
: config-b!  ( data config-addr -- )  ['] rtas-config-b! config-xt ;
: config-w!  ( data config-addr -- )  ['] rtas-config-w! config-xt ;
: config-l!  ( data config-addr -- )  ['] rtas-config-l! config-xt ;

\ for Debug purposes: dumps the whole config space
: config-dump puid >r my-puid TO puid my-space pci-dump r> TO puid ;

\ needed to find the right path in the device tree
: decode-unit ( addr len -- phys.lo ... phys.hi )
        2 hex-decode-unit       \ decode string
        B lshift swap           \ shift the devicenumber to the right spot
        8 lshift or             \ add the functionnumber
        my-bus 10 lshift or     \ add the busnumber
        0 0 rot                 \ make phys.lo = 0 = phys.mid
;

\ needed to have the right unit address in the device tree listing
\ phys.lo=phys.mid=0 , phys.hi=config-address
: encode-unit ( phys.lo ... phys.hi -- unit-str unit-len )
        nip nip                         \ forget the both zeros
        dup 8 rshift 7 and swap         \ calc Functionnumber
        B rshift 1F and                 \ calc Devicenumber
        over IF                         \ IF Function!=0
                2 hex-encode-unit       \ | create string with DevNum,FnNum
        ELSE                            \ ELSE
                nip 1 hex-encode-unit   \ | create string with only DevNum
        THEN                            \ FI
;

: map-in ( phys.lo phys.mid phys.hi size -- virt )
   \ ." map-in called: " .s cr
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
   \ TODO: Use translate-address here!
;

: map-out ( virt size -- )
   \ ." map-out called: " .s cr
   2drop 
;

: dma-alloc ( ... size -- virt )
   \ ." dma-alloc called: " .s cr
   alloc-mem
;

: dma-free ( virt size -- )
   \ ." dma-free called: " .s cr
   free-mem
;

: dma-map-in ( ... virt size cacheable? -- devaddr )
   \ ." dma-map-in called: " .s cr
   2drop
;

: dma-map-out ( virt devaddr size -- )
   \ ." dma-map-out called: " .s cr
   2drop drop
;

: dma-sync ( virt devaddr size -- )
   \ XXX should we add at least a memory barrier here?
   \ ." dma-sync called: " .s cr
   2drop drop
;

: open true ;
: close ;
