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


: fcode-revision ( -- n )
  00030000 \ major * 65536 + minor
  ;

: b(lit) ( -- n )
  next-ip read-fcode-num32
  ?compile-mode IF literal, THEN
  ;

: b(")
  next-ip read-fcode-string
  ?compile-mode IF fc-string, align postpone count THEN
  ;

: b(')
  next-ip read-fcode# get-token drop ?compile-mode IF literal, THEN
  ;

: ?jump-direction ( n -- )
   dup 8000 >= IF
      10000 -           \ Create cell-sized negative value
   THEN
   fcode-offset -       \ IP is already behind offset, so subtract offset size
;

: ?negative
  8000 and
  ;

: dest-on-top
  0 >r BEGIN dup @ 0= WHILE >r REPEAT
       BEGIN r> dup WHILE swap REPEAT
  drop
  ;

: read-fcode-offset
   next-ip
   ?offset16 IF
      read-fcode-num16
   ELSE
      read-byte
      dup 80 and IF FF00 or THEN       \ Fake 16-bit signed offset
   THEN
;

: b?branch ( flag -- )
   ?compile-mode IF
      read-fcode-offset ?negative IF
         dest-on-top postpone until
      ELSE
         postpone if
      THEN
   ELSE
      ( flag ) IF
         fcode-offset jump-n-ip       \ Skip over offset value
      ELSE
         read-fcode-offset
         ?jump-direction jump-n-ip
      THEN
   THEN
; immediate

: bbranch ( -- )
   ?compile-mode IF
      read-fcode-offset
      ?negative IF
         dest-on-top postpone again
      ELSE
         postpone else
         get-ip next-ip fcode@ B2 = IF
            drop
         ELSE
            set-ip
         THEN
      THEN
   ELSE
      read-fcode-offset ?jump-direction jump-n-ip
   THEN
; immediate

: b(<mark) ( -- )
  ?compile-mode IF postpone begin THEN
  ; immediate

: b(>resolve) ( -- )
  ?compile-mode IF postpone then THEN
  ; immediate

: b(;)
   <semicolon> compile, reveal
   postpone [
; immediate

: b(:) ( -- )
  <colon> compile, ]
  ; immediate

: b(case) ( sel -- sel )
  postpone case
  ; immediate

: b(endcase)
  postpone endcase
  ; immediate

: b(of)
  postpone of
  read-fcode-offset drop   \ read and discard offset
  ; immediate

: b(endof)
  postpone endof
  read-fcode-offset drop
  ; immediate

: b(do)
  postpone do
  read-fcode-offset drop
  ; immediate

: b(?do)
  postpone ?do
  read-fcode-offset drop
  ; immediate

: b(loop)
  postpone loop
  read-fcode-offset drop
  ; immediate

: b(+loop)
  postpone +loop
  read-fcode-offset drop
  ; immediate

: b(leave)
  postpone leave
  ; immediate


0 VALUE fc-instance?
: fc-instance  ( -- )   \ Mark next defining word as instance-specific.
   TRUE TO fc-instance?
;

: new-token  \ unnamed local fcode function
  align here next-ip read-fcode# 0 swap set-token
  ;

: external-token ( -- )  \ named local fcode function
  next-ip read-fcode-string
  \ fc-instance? IF cr ." ext instance token: " 2dup type ."  in " pwd cr THEN
  header         ( str len -- )  \ create a header in the current dictionary entry
  new-token
  ;

: new-token
   eva-debug? IF
      s" x" get-ip >r next-ip read-fcode# r> set-ip (u.) $cat strdup
      header
   THEN
   new-token
;

\ decide wether or not to give a new token an own name in the dictionary
: named-token
   fcode-debug? IF
      external-token
   ELSE
      next-ip read-fcode-string 2drop       \ Forget about the name
      new-token
   THEN
;

: b(to) ( val -- )
   next-ip read-fcode#
   get-token drop                           ( val xt )
   dup @                                    ( val xt @xt )
   dup <value> =  over <defer> = OR IF
      \ Destination is value or defer
      drop
      >body cell -
      ( val addr )
      ?compile-mode IF
         literal, postpone !
      ELSE
         !
      THEN
   ELSE
      <create> <> IF                         ( val xt )
         TRUE ABORT" Invalid destination for FCODE b(to)"
      THEN
      dup cell+ @                           ( val xt @xt+1cell )
      dup <instancevalue> <>  swap <instancedefer> <> AND IF
         TRUE ABORT" Invalid destination for FCODE b(to)"
      THEN
      \ Destination is instance-value or instance-defer
      >body @                               ( val instance-offset )
      ?compile-mode IF
         literal,  postpone >instance  postpone !
      ELSE
         >instance !
      THEN
      ELSE
   THEN
; immediate

: b(value)
   fc-instance? IF
      <create> ,                \ Needed for "(instance?)" for example
      <instancevalue> ,
      (create-instance-var)
      FALSE TO fc-instance?
   ELSE
      <value> , ,
   THEN
   reveal
;

: b(variable)
   fc-instance? IF
      <create> ,                \ Needed for "(instance?)"
      <instancevariable> ,
      0 (create-instance-var)
      FALSE TO fc-instance?
   ELSE
      <variable> , 0 ,
   THEN
   reveal
;

: b(constant)
  <constant> , , reveal
  ;

: undefined-defer
  cr cr ." Uninitialized defer word has been executed!" cr cr
  true fcode-end !
  ;

: b(defer)
   fc-instance? IF
      <create> ,                \ Needed for "(instance?)"
      <instancedefer> ,
      ['] undefined-defer (create-instance-var)
      reveal
      FALSE TO fc-instance?
   ELSE
      <defer> , reveal
      postpone undefined-defer
   THEN
;

: b(create)
  <variable> ,
  postpone noop reveal
  ;

: b(field) ( E: addr -- addr+offset ) ( F: offset size -- offset+size )
   <colon> , over literal,
   postpone +
   <semicolon> compile,
   reveal
   +
;

: b(buffer:) ( E: -- a-addr) ( F: size -- )
   fc-instance? IF
      <create> ,                \ Needed for "(instance?)"
      <instancebuffer> ,
      (create-instance-buf)
      FALSE TO fc-instance?
   ELSE
      <buffer:> , allot
   THEN
   reveal
;

: suspend-fcode ( -- )
  noop        \ has to be implemented more efficiently ;-)
  ;

: offset16 ( -- )
  2 to fcode-offset
  ;

: version1 ( -- )
  1 to fcode-spread
  1 to fcode-offset
  read-header
  ;

: start0 ( -- )
  0 to fcode-spread
  offset16
  read-header
  ;

: start1 ( -- )
  1 to fcode-spread
  offset16
  read-header
  ;

: start2 ( -- )
  2 to fcode-spread
  offset16
  read-header
  ;

: start4 ( -- )
  4 to fcode-spread
  offset16
  read-header
  ;

: end0 ( -- )
  true fcode-end !
  ;

: end1 ( -- )
  end0
  ;

: ferror ( -- )
  clear end0
  cr ." FCode# " fcode-num @ . ." not assigned!"
  cr ." FCode evaluation aborted." cr
  ." ( -- S:" depth . ." R:" rdepth . ." ) " .s cr
  abort
  ;

: reset-local-fcodes
  FFF 800 DO ['] ferror 0 i set-token LOOP
  ;

: byte-load ( addr xt -- )
  >r >r
  save-evaluator-state
  r> r>
  reset-fcode-end
  1 to fcode-spread
  dup 1 = IF drop ['] rb@ THEN to fcode-rb@
  set-ip
  reset-local-fcodes
  depth >r
  evaluate-fcode
  r> depth 1- <> IF
      clear end0
      cr ." Ambiguous stack depth after byte-load!"
      cr ." FCode evaluation aborted." cr cr
  ELSE
      restore-evaluator-state
  THEN
  ['] c@ to fcode-rb@
;

\ Functions for accessing memory ... since some FCODE programs use the normal
\ memory access functions for accessing MMIO memory, too, we got to use a little
\ hack to support them: When address is bigger than MIN-RAM-SIZE, assume the
\ FCODE is trying to access MMIO memory and use the register based access
\ functions instead!
: fc-c@   ( addr -- byte )   dup MIN-RAM-SIZE > IF rb@ ELSE c@ THEN ;
: fc-w@   ( addr -- word )   dup MIN-RAM-SIZE > IF rw@ ELSE w@ THEN ;
: fc-<w@  ( addr -- word )   fc-w@ dup 8000 >= IF 10000 - THEN ;
: fc-l@   ( addr -- long )   dup MIN-RAM-SIZE > IF rl@ ELSE l@ THEN ;
: fc-<l@  ( addr -- long )   fc-l@ signed ;
: fc-x@   ( addr -- dlong )  dup MIN-RAM-SIZE > IF rx@ ELSE x@ THEN ;
: fc-c!   ( byte addr -- )   dup MIN-RAM-SIZE > IF rb! ELSE c! THEN ;
: fc-w!   ( word addr -- )   dup MIN-RAM-SIZE > IF rw! ELSE w! THEN ;
: fc-l!   ( long addr -- )   dup MIN-RAM-SIZE > IF rl! ELSE l! THEN ;
: fc-x!   ( dlong addr -- )  dup MIN-RAM-SIZE > IF rx! ELSE x! THEN ;

: fc-fill ( add len byte -- )  2 pick MIN-RAM-SIZE > IF rfill ELSE fill THEN ;
: fc-move ( src dst len -- )
   2 pick MIN-RAM-SIZE >        \ Check src
   2 pick MIN-RAM-SIZE >        \ Check dst
   OR IF rmove ELSE move THEN
;

\ Destroy virtual mapping (should maybe also update "address" property here?)
: free-virtual  ( virt size -- )
   s" map-out" $call-parent
;

\ Map the specified region, return virtual address
: map-low  ( phys.lo ... size -- virt )
    my-space swap s" map-in" $call-parent
;

\ Get MAC address
: mac-address  ( -- mac-str mac-len )
   s" local-mac-address" get-my-property IF
      0 0
   THEN
;

\ Output line and column number - not used yet
VARIABLE #line
0 #line !
VARIABLE #out
0 #out !

\ Display device status
: display-status  ( n -- )
   ." Device status: " . cr
;

\ Obsolete variables:
VARIABLE group-code
0 group-code !

\ Obsolete: Allocate memory for DMA
: dma-alloc  ( byte -- virtual )
   s" dma-alloc" $call-parent
;

\ Obsolete: Get params property
: my-params  ( -- addr len )
   s" params" get-my-property IF
      0 0
   THEN
;

\ Obsolete: Convert SBus interrupt level to CPU interrupt level
: sbus-intr>cpu  ( sbus-intr# -- cpu-intr# )
;

\ Obsolete: Set "intr" property
: intr  ( interrupt# vector -- )
   >r sbus-intr>cpu encode-int r> encode-int+ s" intr" property
;

\ Obsolete: Create the "name" property
: driver  ( addr len -- )
   encode-string s" name" property
;

\ Obsolete: Return type of CPU
: processor-type  ( -- cpu-type )
   0
;

\ Obsolete: Return firmware version
: firmware-version  ( -- n )
   10000                          \ Just a dummy value
;

\ Obsolete: Return fcode-version
: fcode-version  ( -- n )
   fcode-revision
;
