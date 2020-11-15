\ *****************************************************************************
\ * Copyright (c) 2011 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/
\ *
\ * Support for old-fashioned local values in FCODE.
\ *
\ * There is one old FCODE tokenizer that uses the FCODE opcodes in the range
\ * of 0x407 to 0x41f for supporting Forth local values. Each locals stack
\ * frame contains 8 variables. The opcodes from 0x407 to 0x40f are used to
\ * push 0 up to 8 values from the normal data stack into the current locals
\ * stack frame. All other variables in the current stack frame are not
\ * pre-initialized.
\ * The opcodes from 0x410 to 0x417 can be used for reading the first, second,
\ * ... eighth value out of the locals stack frame, and the opcode from 0x418
\ * to 0x41f can be used to set the first, second, ... eighth value in the
\ * stack frame respectively.
\ *

80 cells CONSTANT LOCALS-STACK-SIZE

LOCALS-STACK-SIZE BUFFER: localsstackbuf

localsstackbuf VALUE localsstack


: fc-local@  ( n -- val )
   cells localsstack swap - @
;

: fc-local-1-@  1 fc-local@ ;
: fc-local-2-@  2 fc-local@ ;
: fc-local-3-@  3 fc-local@ ;
: fc-local-4-@  4 fc-local@ ;
: fc-local-5-@  5 fc-local@ ;
: fc-local-6-@  6 fc-local@ ;
: fc-local-7-@  7 fc-local@ ;
: fc-local-8-@  8 fc-local@ ;


: fc-local!  ( val n -- )
   cells localsstack swap - !
;

: fc-local-1-!  1 fc-local! ;
: fc-local-2-!  2 fc-local! ;
: fc-local-3-!  3 fc-local! ;
: fc-local-4-!  4 fc-local! ;
: fc-local-5-!  5 fc-local! ;
: fc-local-6-!  6 fc-local! ;
: fc-local-7-!  7 fc-local! ;
: fc-local-8-!  8 fc-local! ;


0 VALUE uses-locals?

\ Create space for the current function on the locals stack.
\ Pre-initialized the n first locals with the n top-most data stack items.
\ Note: Each function can use up to 8 (initialized or uninitialized) locals.
: (fc-push-locals)  ( ... n -- )
   \ cr ." pushing " dup . ." locals" cr
   8 cells localsstack + TO localsstack
   localsstack localsstackbuf -
   LOCALS-STACK-SIZE > ABORT" Locals stack exceeded!"
   ?dup IF
      ( ... n ) 1 swap DO
         i fc-local!              \ Store pre-initialized locals
      -1 +LOOP
   THEN
;

: fc-push-locals  ( n -- )
   \ cr ." compiling push for " dup . ." locals" cr
   uses-locals? ABORT" Definition pushes locals multiple times!"
   true TO uses-locals?
   ( n ) ['] literal execute
   ['] (fc-push-locals) compile,
;

: fc-push-0-locals  0 fc-push-locals ;
: fc-push-1-locals  1 fc-push-locals ;
: fc-push-2-locals  2 fc-push-locals ;
: fc-push-3-locals  3 fc-push-locals ;
: fc-push-4-locals  4 fc-push-locals ;
: fc-push-5-locals  5 fc-push-locals ;
: fc-push-6-locals  6 fc-push-locals ;
: fc-push-7-locals  7 fc-push-locals ;
: fc-push-8-locals  8 fc-push-locals ;


: fc-pop-locals  ( -- )
   \ ." popping locals" cr
   localsstack 8 cells - TO localsstack
   localsstack localsstackbuf - 0 < ABORT" Locals stack undeflow!"
;


: fc-locals-exit
   uses-locals? IF
      \ ." compiling pop-locals for exit" cr
      ['] fc-pop-locals compile,
   THEN
   ['] exit compile,
;

: fc-locals-b(;)
   uses-locals? IF
      \ ." compiling pop-locals for b(;)" cr
      ['] fc-pop-locals compile,
   THEN
   false TO uses-locals?
   ['] b(;) execute
;


: fc-set-locals-tokens  ( -- )
   ['] fc-push-0-locals 1 407 set-token
   ['] fc-push-1-locals 1 408 set-token
   ['] fc-push-2-locals 1 409 set-token
   ['] fc-push-3-locals 1 40a set-token
   ['] fc-push-4-locals 1 40b set-token
   ['] fc-push-5-locals 1 40c set-token
   ['] fc-push-6-locals 1 40d set-token
   ['] fc-push-7-locals 1 40e set-token
   ['] fc-push-8-locals 1 40f set-token

   ['] fc-local-1-@ 0 410 set-token
   ['] fc-local-2-@ 0 411 set-token
   ['] fc-local-3-@ 0 412 set-token
   ['] fc-local-4-@ 0 413 set-token
   ['] fc-local-5-@ 0 414 set-token
   ['] fc-local-6-@ 0 415 set-token
   ['] fc-local-7-@ 0 416 set-token
   ['] fc-local-8-@ 0 417 set-token

   ['] fc-local-1-! 0 418 set-token
   ['] fc-local-2-! 0 419 set-token
   ['] fc-local-3-! 0 41a set-token
   ['] fc-local-4-! 0 41b set-token
   ['] fc-local-5-! 0 41c set-token
   ['] fc-local-6-! 0 41d set-token
   ['] fc-local-7-! 0 41e set-token
   ['] fc-local-8-! 0 41f set-token

   ['] fc-locals-exit 1 33 set-token
   ['] fc-locals-b(;) 1 c2 set-token
;
fc-set-locals-tokens
