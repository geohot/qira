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

STRUCT
   cell FIELD >r0   cell FIELD >r1   cell FIELD >r2   cell FIELD >r3
   cell FIELD >r4   cell FIELD >r5   cell FIELD >r6   cell FIELD >r7
   cell FIELD >r8   cell FIELD >r9   cell FIELD >r10  cell FIELD >r11
   cell FIELD >r12  cell FIELD >r13  cell FIELD >r14  cell FIELD >r15
   cell FIELD >r16  cell FIELD >r17  cell FIELD >r18  cell FIELD >r19
   cell FIELD >r20  cell FIELD >r21  cell FIELD >r22  cell FIELD >r23
   cell FIELD >r24  cell FIELD >r25  cell FIELD >r26  cell FIELD >r27
   cell FIELD >r28  cell FIELD >r29  cell FIELD >r30  cell FIELD >r31
   cell FIELD >cr   cell FIELD >xer  cell FIELD >lr   cell FIELD >ctr
   cell FIELD >srr0 cell FIELD >srr1 cell FIELD >dar  cell FIELD >dsisr
CONSTANT ciregs-size



: .16  10 0.r 3 spaces ;
: .8   8 spaces 8 0.r 3 spaces ;
: .4regs  cr 4 0 DO dup @ .16 8 cells+ LOOP drop ;
: .fixed-regs
   cr ."     R0 .. R7           R8 .. R15         R16 .. R23         R24 .. R31"
   dup 8 0 DO dup .4regs cell+ LOOP drop
;

: .special-regs
   cr ."     CR / XER           LR / CTR          SRR0 / SRR1        DAR / DSISR"
   cr dup >cr  @ .8   dup >lr  @ .16  dup >srr0 @ .16  dup >dar @ .16
   cr dup >xer @ .16  dup >ctr @ .16  dup >srr1 @ .16    >dsisr @ .8
;

: .regs
   cr .fixed-regs
   cr .special-regs
   cr cr
;

: .hw-exception ( reason-code exception-nr -- )
   ." ( " dup . ." ) "
   CASE
      200 OF ." Machine Check" ENDOF
      300 OF ." Data Storage" ENDOF
      380 OF ." Data Segment" ENDOF
      400 OF ." Instruction Storage" ENDOF
      480 OF ." Instruction Segment" ENDOF
      500 OF ." External" ENDOF
      600 OF ." Alignment" ENDOF
      700 OF ." Program" ENDOF
      800 OF ." Floating-point unavailable" ENDOF
      900 OF ." Decrementer" ENDOF
      980 OF ." Hypervisor Decrementer" ENDOF
      C00 OF ." System Call" ENDOF
      D00 OF ." Trace" ENDOF
      F00 OF ." Performance Monitor" ENDOF
      F20 OF ." VMX Unavailable" ENDOF
      1200 OF ." System Error" ENDOF
      1600 OF ." Maintenance" ENDOF
      1800 OF ." Thermal" ENDOF
      dup OF ." Unknown" ENDOF
   ENDCASE
   ."  Exception [ " . ." ]"
;

: .sw-exception ( exception-nr -- )
   ."  Exception [ " . ." ] triggered by boot firmware."
;

\ this word gets also called for non-hardware exceptions.
: be-hw-exception ( [reason-code] exception-nr -- )
   cr cr
   dup 0> IF .hw-exception ELSE .sw-exception THEN
   cr eregs .regs
;
' be-hw-exception to hw-exception-handler

: (boot-exception-handler) ( x1...xn exception-nr -- x1...xn)
   dup IF
      dup 0 > IF
	 negate cp 9 emit ." : " type
      ELSE
	 CASE
	    -6d OF cr ." W3411: Client application returned." cr ENDOF
	    -6c OF cr ." E3400: It was not possible to boot from any device "
		." specified in the VPD." cr
	    ENDOF
	    -6b OF cr ." E3410: Boot list successfully read from VPD "
		." but no useful information received." cr
	    ENDOF
	    -6a OF cr ." E3420: Boot list could not be read from VPD." cr
	    ENDOF
	    -69 OF
	        cr ." E3406: Client application returned an error"
		abort"-str @ count dup IF
		   ." :    " type cr
		ELSE
		   ." ." cr
		   2drop
		THEN
	    ENDOF
	    -68 OF cr ." E3405: No such device" cr ENDOF
	    -67 OF cr ." E3404: Not a bootable device!" cr ENDOF
	    -66 OF cr ." E3408: Failed to claim memory for the executable" cr
	    ENDOF
	    -65 OF cr ." E3407: Load failed" cr ENDOF
	    -64 OF cr ." E3403: Bad executable:   " abort"-str @ count type cr
	    ENDOF
	    -63 OF cr ." E3409: Unknown FORTH Word" cr ENDOF
	    -2 OF cr ." E3401: Aborting boot,  " abort"-str @ count type cr
	    ENDOF
	    dup OF ." E3402: Aborting boot, internal error" cr ENDOF
	 ENDCASE
      THEN
   ELSE
      drop
   THEN
;

' (boot-exception-handler) to boot-exception-handler

: throw-error ( error-code "error-string" -- )
   skipws 0a parse rot throw
;

\ Enable external interrupt in msr

: enable-ext-int ( -- )
   msr@ 8000 or msr!
;

\ Disable external interrupt in msr

: disable-ext-int ( -- )
   msr@ 8000 not and msr!
;

\ Generate external interrupt through Internal Interrupt Controller of BE

: gen-ext-int ( -- )
   7fffffff dec!               \ Reset decrementer
   enable-ext-int              \ Enable interrupt
   FF 20000508418 rx!          \ Interrupt priority mask
   10 20000508410 rx!          \ Interrupt priority
;

