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


\ Get the name of Forth command whose execution token is xt

: xt>name ( xt -- str len )
    BEGIN
	cell - dup c@ 0 2 within IF
	    dup 2+ swap 1+ c@ exit
	THEN
    AGAIN
;

cell -1 * CONSTANT -cell
: cell- ( n -- n-cell-size )
   [ cell -1 * ] LITERAL +
;

\ Search for xt of given address
: find-xt-addr ( addr -- xt )
   BEGIN
      dup @ <colon> = IF
	 EXIT
      THEN
      cell-
   AGAIN
;

: (.immediate) ( xt -- )
   \ is it immediate?
   xt>name drop 2 - c@ \ skip len and flags
   immediate? IF
     ."  IMMEDIATE"
   THEN
;

: (.xt) ( xt -- )
   xt>name type
;

\ Trace back on current return stack.
\ Start at 1, since 0 is return of trace-back itself

: trace-back (  )
   1
   BEGIN
      cr dup dup . ."  : " rpick dup . ."  : "
      ['] tib here within IF
	  dup rpick find-xt-addr (.xt)
      THEN
      1+ dup rdepth 5 - >= IF cr drop EXIT THEN
   AGAIN
;

VARIABLE see-my-type-column

: (see-my-type) ( indent limit xt str len -- indent limit xt )
   dup see-my-type-column @ + dup 50 >= IF
      -rot over "  " comp 0= IF
         \ blank causes overflow: just enforce new line with next call
         2drop see-my-type-column !
      ELSE
         rot drop                     ( indent limit xt str len )
         \ Need to copy string since we use (u.) again (kills internal buffer):
         pocket swap 2dup >r >r       ( indent limit xt str pk len  R: len pk )
         move r> r>                   ( indent limit xt pk len )
         2 pick (u.) dup -rot
         cr type                      ( indent limit xt pk len xt-len )
         " :" type 1+                 ( indent limit xt pk len prefix-len )
         5 pick dup spaces +          ( indent limit xt pk len prefix-len )
         over + see-my-type-column !  ( indent limit xt pk len )
         type
      THEN                            ( indent limit xt )
   ELSE
      see-my-type-column ! type       ( indent limit xt )
   THEN
;

: (see-my-type-init) ( -- )
   ffff see-my-type-column !        \ just enforce a new line
;

: (see-colon-body) ( indent limit xt -- indent limit xt )
   (see-my-type-init)                              \ enforce new line
   BEGIN                                           ( indent limit xt )
      cell+ 2dup <>
      over @
      dup <semicolon> <>
      rot and			                   ( indent limit xt @xt flag )
   WHILE                                           ( indent limit xt @xt )
      xt>name (see-my-type) "  " (see-my-type)
      dup @                                        ( indent limit xt @xt)
      CASE
	 <0branch>  OF cell+ dup @
                    over + cell+ dup >r
                    (u.) (see-my-type) r>          ( indent limit xt target)
                    2dup < IF
                       over 4 pick 3 + -rot recurse
                       nip nip nip cell-           ( indent limit xt )
                    ELSE
                       drop                        ( indent limit xt )
                    THEN
                    (see-my-type-init) ENDOF       \ enforce new line
	 <branch>   OF cell+ dup @ over + cell+ (u.)
                    (see-my-type) "  " (see-my-type) ENDOF
	 <do?do>    OF cell+ dup @ (u.) (see-my-type)
                    "  " (see-my-type) ENDOF
	 <lit>      OF cell+ dup @ (u.) (see-my-type)
                    "  " (see-my-type) ENDOF
	 <dotick>   OF cell+ dup @ xt>name (see-my-type)
                    "  " (see-my-type) ENDOF
	 <doloop>   OF cell+ dup @ (u.) (see-my-type)
                    "  " (see-my-type) ENDOF
	 <do+loop>  OF cell+ dup @ (u.) (see-my-type)
                    "  " (see-my-type) ENDOF
	 <doleave>  OF cell+ dup @ over + cell+ (u.)
                    (see-my-type) "  " (see-my-type) ENDOF
	 <do?leave> OF cell+ dup @ over + cell+ (u.)
                    (see-my-type) "  " (see-my-type) ENDOF
	 <sliteral> OF cell+ " """ (see-my-type) dup count dup >r
                    (see-my-type) " """ (see-my-type)
                    "  " (see-my-type)
                    r> -cell and + ENDOF
      ENDCASE
   REPEAT
   drop
;

: (see-colon) ( xt -- )
   (see-my-type-init)
   1 swap 0 swap                                    ( indent limit xt )
   " : " (see-my-type) dup xt>name (see-my-type)
   rot drop 4 -rot (see-colon-body)                 ( indent limit xt )
   rot drop 1 -rot (see-my-type-init) " ;" (see-my-type)
   3drop 
;

\ Create words are a bit tricky. We find out where their code points.
\ If this code is part of SLOF, it is not a user generated CREATE.

: (see-create) ( xt -- )
   dup cell+ @
   CASE
      <2constant> OF
         dup cell+ cell+ dup @ swap cell+ @ . .  ." 2CONSTANT "
      ENDOF

      <instancevalue> OF
         dup cell+ cell+ @ . ." INSTANCE VALUE "
      ENDOF

      <instancevariable> OF
         ." INSTANCE VARIABLE "
      ENDOF

      dup OF
         ." CREATE "
      ENDOF
   ENDCASE
   (.xt)
;

\ Decompile Forth command whose execution token is xt

: (see) ( xt -- )
   cr dup dup @
   CASE
      <variable> OF ." VARIABLE " (.xt) ENDOF
      <value>    OF dup execute . ." VALUE " (.xt) ENDOF
      <constant> OF dup execute . ." CONSTANT " (.xt) ENDOF
      <defer>    OF dup cell+ @ swap ." DEFER " (.xt) ."  is " (.xt) ENDOF
      <alias>    OF dup cell+ @ swap ." ALIAS " (.xt) ."  " (.xt) ENDOF
      <buffer:>  OF ." BUFFER: " (.xt) ENDOF
      <create>   OF (see-create) ENDOF
      <colon>    OF (see-colon)  ENDOF
      dup        OF ." ??? PRIM " (.xt) ENDOF
   ENDCASE
   (.immediate) cr
  ;

\ Decompile Forth command old-name

: see ( "old-name<>" -- )
   ' (see)
;

\ Work in progress...

0    value forth-ip
true value trace>stepping?
true value trace>print?
true value trace>up?
0    value trace>depth
0    value trace>rdepth
0    value trace>recurse
: trace-depth+ ( -- ) trace>depth 1+ to trace>depth ;
: trace-depth- ( -- ) trace>depth 1- to trace>depth ;

: stepping ( -- )
    true to trace>stepping?
;

: tracing ( -- )
    false to trace>stepping?
;

: trace-print-on ( -- )
    true to trace>print?
;

: trace-print-off ( -- )
    false to trace>print?
;


\ Add n to ip

: fip-add ( n -- )
   forth-ip + to forth-ip
;

\ Save execution token address and content

0 value debug-last-xt
0 value debug-last-xt-content

: trace-print ( -- )
   forth-ip cr u. ." : "
   forth-ip @ 
   dup ['] breakpoint = IF drop debug-last-xt-content THEN
   xt>name type ."  "
   ."     ( " .s  ."  )  | "
;

: trace-interpret ( -- )
   rdepth 1- to trace>rdepth
   BEGIN
      depth . [char] > dup emit emit space
      source expect                        ( str len )
      ['] interpret catch print-status
   AGAIN
;

\ Main trace routine, trace a colon definition

: trace-xt ( xt -- )
    trace>recurse IF
       r> drop                                \ Drop return of 'trace-xt call
       cell+                                  \ Step over ":"
    ELSE
       debug-last-xt-content <colon> = IF
          \ debug colon-definition
          ['] breakpoint @ debug-last-xt !    \ Re-arm break point
          r> drop                             \ Drop return of 'trace-xt call
          cell+                               \ Step over ":"
       ELSE
          ['] breakpoint debug-last-xt !      \ Re-arm break point
          2r> 2drop
       THEN
    THEN

    to forth-ip
    true to trace>print?
    BEGIN
       trace>print? IF trace-print THEN

       forth-ip                                              ( ip )
       trace>stepping? IF
	  BEGIN
             key
             CASE
		[char] d OF dup @ @ <colon> = IF             \ recurse only into colon definitions
			                         trace-depth+
                                                 1 to trace>recurse
                                                 dup >r @ recurse
		                              THEN true ENDOF
	        [char] u OF trace>depth IF tracing trace-print-off true ELSE false THEN ENDOF
	        [char] f OF drop cr trace-interpret ENDOF	\ quit trace and start interpreter FIXME rstack
	        [char] c OF tracing true ENDOF
		[char] t OF trace-back false ENDOF
		[char] q OF drop cr quit ENDOF
	        20       OF true ENDOF
		dup      OF cr ." Press d:       Down into current word" cr
		            ." Press u:       Up to caller" cr
		            ." Press f:       Switch to forth interpreter, 'resume' will continue tracing" cr
                            ." Press c:       Switch to tracing" cr
		            ." Press <space>: Execute current word" cr
		            ." Press q:       Abort execution, switch to interpreter" cr
		            false ENDOF
	     ENDCASE
	  UNTIL
       THEN	                                              ( ip' )
       dup to forth-ip @                                      ( xt )
       dup ['] breakpoint = IF drop debug-last-xt-content THEN
       dup                                                    ( xt xt )

       CASE
	    <sliteral>  OF drop forth-ip cell+ dup dup c@ + -cell and to forth-ip ENDOF
	    <dotick>    OF drop forth-ip cell+ @ cell fip-add ENDOF
	    <lit>       OF drop forth-ip cell+ @ cell fip-add ENDOF
	    <doto>      OF drop forth-ip cell+ @ cell+ ! cell fip-add ENDOF
	    <(doito)>   OF drop forth-ip cell+ @ cell+ cell+ @ >instance ! cell fip-add ENDOF
	    <0branch>   OF drop IF
		                    cell fip-add
		                ELSE
				    forth-ip cell+ @ cell+ fip-add THEN
			ENDOF
            <do?do>     OF drop 2dup <> IF
				           swap >r >r cell fip-add
		                        ELSE
					   forth-ip cell+ @ cell+ fip-add 2drop THEN
		        ENDOF
	    <branch>    OF drop forth-ip cell+ @ cell+ fip-add ENDOF
	    <doleave>   OF drop r> r> 2drop forth-ip cell+ @ cell+ fip-add ENDOF		
	    <do?leave>  OF drop IF
		                   r> r> 2drop forth-ip cell+ @ cell+ fip-add
		                ELSE
		                   cell fip-add
		                THEN
		        ENDOF		
	    <doloop>    OF drop r> 1+ r> 2dup = IF
		                                   2drop cell fip-add
		                                ELSE >r >r
						    forth-ip cell+ @ cell+ fip-add THEN
			ENDOF
	    <do+loop>   OF drop r> + r> 2dup >= IF
		                                   2drop cell fip-add
		                                ELSE >r >r
						    forth-ip cell+ @ cell+ fip-add THEN
			ENDOF

	    <semicolon> OF trace>depth 0> IF
		                             trace-depth- 1 to trace>recurse
                                             stepping drop r> recurse
		                          ELSE
		                             drop exit THEN
			ENDOF
            <exit>      OF trace>depth 0> IF
		                             trace-depth- stepping drop r> recurse
		                          ELSE
				             drop exit THEN
			ENDOF
	    dup         OF execute ENDOF
	ENDCASE
	forth-ip cell+ to forth-ip
    AGAIN
;

\ Resume execution from tracer
: resume ( -- )
    trace>rdepth rdepth!
    forth-ip cell - trace-xt
;

\ Turn debug off, by erasing breakpoint

: debug-off ( -- )
    debug-last-xt IF
	debug-last-xt-content debug-last-xt !  \ Restore overwritten token
	0 to debug-last-xt
    THEN
;



\ Entry point for debug

: (break-entry) ( -- )
   debug-last-xt dup @ ['] breakpoint <> swap  ( debug-addr? debug-last-xt )
   debug-last-xt-content swap !                \ Restore overwritten token
   r> drop                                     \ Don't return to bp, but to caller
   debug-last-xt-content <colon> <> and IF     \ Execute non colon definition
      debug-last-xt cr u. ." : "
      debug-last-xt xt>name type ."  "
      ."     ( " .s  ."  )  | "
      key drop
      debug-last-xt execute
   ELSE
      debug-last-xt 0 to trace>depth 0 to trace>recurse trace-xt   \ Trace colon definition
   THEN
;

\ Put entry point bp defer
' (break-entry) to BP

\ Mark an address for debugging

: debug-address ( addr --  )
   debug-off                       ( xt )  \ Remove active breakpoint
   dup to debug-last-xt            ( xt )  \ Save token for later debug
   dup @ to debug-last-xt-content  ( xt )  \ Save old value
   ['] breakpoint swap !
;

\ Mark the command indicated by xt for debugging

: (debug ( xt --  )
   debug-off                       ( xt )  \ Remove active breakpoint
   dup to debug-last-xt            ( xt )  \ Save token for later debug
   dup @ to debug-last-xt-content  ( xt )  \ Save old value
   ['] breakpoint @ swap !
;

\ Mark the command indicated by xt for debugging

: debug ( "old-name<>" -- )
    parse-word $find IF                       \ Get xt for old-name
       (debug
    ELSE
       ." undefined word " type cr
    THEN
;
