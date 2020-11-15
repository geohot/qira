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

: ?offset16 ( -- true|false )
  fcode-offset 2 =
  ;

: ?arch64 ( -- true|false )
  cell 8 =
  ;

: ?bigendian ( -- true|false )
  deadbeef fcode-num !
  fcode-num ?arch64 IF 4 + THEN
  c@ de =
  ;

: reset-fcode-end ( -- )
  false fcode-end !
  ;

: get-ip ( -- n )
  ip @
  ;

: set-ip ( n -- )
  ip !
  ;

: next-ip ( -- )
  get-ip 1+ set-ip
  ;

: jump-n-ip ( n -- )
  get-ip + set-ip
  ;

: read-byte ( -- n )
  get-ip fcode-rb@
  ;

: ?compile-mode ( -- on|off )
  state @
  ;

: save-evaluator-state
  get-ip               eva-debug? IF ." saved ip "           dup . cr THEN
  fcode-end @          eva-debug? IF ." saved fcode-end "    dup . cr THEN
  fcode-offset         eva-debug? IF ." saved fcode-offset " dup . cr THEN
\ local fcodes are currently NOT saved!
  fcode-spread         eva-debug? IF ." saved fcode-spread " dup . cr THEN
  ['] fcode@ behavior  eva-debug? IF ." saved fcode@ "       dup . cr THEN
  ;

: restore-evaluator-state
  eva-debug? IF ." restored fcode@ "       dup . cr THEN  to fcode@
  eva-debug? IF ." restored fcode-spread " dup . cr THEN  to fcode-spread
\ local fcodes are currently NOT restored!
  eva-debug? IF ." restored fcode-offset " dup . cr THEN  to fcode-offset
  eva-debug? IF ." restored fcode-end "    dup . cr THEN  fcode-end !
  eva-debug? IF ." restored ip "           dup . cr THEN  set-ip
  ;

: token-table-index ( fcode# -- addr )
  cells token-table +
  ;

: join-immediate ( xt immediate? addr -- xt+immediate? addr )
  -rot + swap
  ;

: split-immediate ( xt+immediate? -- xt immediate? )
  dup 1 and 2dup - rot drop swap
  ;

: literal, ( n -- )
  postpone literal
  ;

: fc-string,
  postpone sliteral
  dup c, bounds ?do i c@ c, loop
  ;

: set-token ( xt immediate? fcode# -- )
  token-table-index join-immediate !
  ;

: get-token ( fcode# -- xt immediate? )
  token-table-index @ split-immediate
  ;

( ---------------------------------------------------- )

#include "little-big.fs"

( ---------------------------------------------------- )

: read-fcode# ( -- FCode# )
  read-byte
  dup 01 0F between IF drop read-fcode-num16 THEN
  ;

: read-header ( adr -- )
  next-ip read-byte        drop
  next-ip read-fcode-num16 drop
  next-ip read-fcode-num32 drop
  ;

: read-fcode-string ( -- str len )
  read-byte            \ get string length ( -- len )
  next-ip get-ip       \ get string addr   ( -- len str )
  swap                 \ type needs the parameters swapped ( -- str len )
  dup 1- jump-n-ip     \ jump to the end of the string in FCode
  ;


-1 VALUE break-fcode-addr
0 VALUE break-fcode-steps

: evaluate-fcode ( -- )
   BEGIN
      get-ip break-fcode-addr = IF
         TRUE fcode-end !
      THEN
      fcode-end @ 0=
   WHILE
      fcode@                               ( fcode# )
      eva-debug? IF
         dup
         get-ip 8 u.r ." : "
         ." [" 3 u.r ." ] "
      THEN
      \ When it is not immediate and in compile-mode, then compile
      get-token 0= ?compile-mode AND IF    ( xt )
         compile,
      ELSE                                 \ immediate or "interpretation" mode
         eva-debug? IF dup xt>name type space THEN
         execute
      THEN
      eva-debug? IF .s cr THEN
      break-fcode-steps IF
         break-fcode-steps 1- TO break-fcode-steps
         break-fcode-steps 0= IF
            TRUE fcode-end !
         THEN
      THEN
      next-ip
   REPEAT
;

\ Run FCODE for n steps
: steps-fcode  ( n -- )
   to break-fcode-steps
   break-fcode-addr >r -1 to break-fcode-addr
   reset-fcode-end
   evaluate-fcode
   r> to break-fcode-addr
;

\ Step through one FCODE instruction
: step-fcode  ( -- )
   1 steps-fcode
;
