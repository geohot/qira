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

\ Hash for faster lookup
#include <find-hash.fs>

: >name ( xt -- nfa ) \ note: still has the "immediate" field!
   BEGIN char- dup c@ UNTIL ( @lastchar )
   dup dup aligned - cell+ char- ( @lastchar lenmodcell )
   dup >r -
   BEGIN dup c@ r@ <> WHILE
      cell- r> cell+ >r
   REPEAT
   r> drop char-
;

\ Words missing in *.in files
VARIABLE mask -1 mask !

VARIABLE huge-tftp-load 1 huge-tftp-load !
\ Default implementation for sms-get-tftp-blocksize that return 1432 (decimal)
: sms-get-tftp-blocksize 598 ;

: default-hw-exception s" Exception #" type . ;

' default-hw-exception to hw-exception-handler

: diagnostic-mode? false ;	\ 2B DOTICK'D later in envvar.fs

: memory-test-suite ( addr len -- fail? )
	diagnostic-mode? IF
		." Memory test mask value: " mask @ . cr
		." No memory test suite currently implemented! " cr
	THEN
	false
;

: 0.r  0 swap <# 0 ?DO # LOOP #> type ;

\ count the number of bits equal 1
\ the idea is to clear in each step the least significant bit
\ v&(v-1) does exactly this, so count the steps until v == 0
: cnt-bits  ( 64-bit-value -- #bits=1 )
	dup IF
		41 1 DO dup 1- and dup 0= IF drop i LEAVE THEN LOOP
	THEN
;

: bcd-to-bin  ( bcd -- bin )
   dup f and swap 4 rshift a * +
;

\ calcs the exponent of the highest power of 2 not greater than n
: 2log ( n -- lb{n} )
   8 cells 0 DO 1 rshift dup 0= IF drop i LEAVE THEN LOOP
;

\ calcs the exponent of the lowest power of 2 not less than n
: log2  ( n -- log2-n )
   1- 2log 1+
;


CREATE $catpad 400 allot
: $cat ( str1 len1 str2 len2 -- str3 len3 )
   >r >r dup >r $catpad swap move
   r> dup $catpad + r> swap r@ move
   r> + $catpad swap ;

\ WARNING: The following two ($cat-comm & $cat-space) are dirty in a sense
\ that they add 1 or 2 characters to str1 before executing $cat
\ The ASSUMPTION is that str1 buffer provides that extra space and it is
\ responsibility of the code owner to ensure that
: $cat-comma ( str2 len2 str1 len1 -- "str1, str2" len1+len2+2 )
	2dup + s" , " rot swap move 2+ 2swap $cat
;

: $cat-space ( str2 len2 str1 len1 -- "str1 str2" len1+len2+1 )
	2dup + bl swap c! 1+ 2swap $cat
;
: $cathex ( str len val -- str len' )
   (u.) $cat
;


: 2CONSTANT    CREATE , , DOES> [ here ] 2@ ;

\ Save XT of 2CONSTANT, put on the stack by "[ here ]" :
CONSTANT <2constant>

: $2CONSTANT  $CREATE , , DOES> 2@ ;

: 2VARIABLE    CREATE 0 , 0 ,  DOES> ;


: (is-user-word) ( name-str name-len xt -- ) -rot $CREATE , DOES> @ execute ;

: zplace ( str len buf -- )  2dup + 0 swap c! swap move ;
: rzplace ( str len buf -- )  2dup + 0 swap rb! swap rmove ;

: strdup ( str len -- dupstr len ) here over allot swap 2dup 2>r move 2r> ;

: str= ( str1 len1 str2 len2 -- equal? )
  rot over <> IF 3drop false ELSE comp 0= THEN ;

: test-string ( param len -- true | false )
   0 ?DO
      dup i + c@                     \ Get character / byte at current index
      dup 20 <  swap 7e >  OR IF     \ Is it out of range 32 to 126 (=ASCII)
         drop FALSE UNLOOP EXIT      \ FALSE means: No ASCII string
      THEN
   LOOP
   drop TRUE    \ Only ASCII found --> it is a string
;

: #aligned ( adr alignment -- adr' ) negate swap negate and negate ;
: #join  ( lo hi #bits -- x )  lshift or ;
: #split ( x #bits -- lo hi )  2dup rshift dup >r swap lshift xor r> ;

: /string ( str len u -- str' len' )
  >r swap r@ chars + swap r> - ;
: skip ( str len c -- str' len' )
  >r BEGIN dup WHILE over c@ r@ = WHILE 1 /string REPEAT THEN r> drop ;
: scan ( str len c -- str' len' )
  >r BEGIN dup WHILE over c@ r@ <> WHILE 1 /string REPEAT THEN r> drop ;
: split ( str len char -- left len right len )
  >r 2dup r> findchar IF >r over r@ 2swap r> 1+ /string ELSE 0 0 THEN ;
\ reverse findchar -- search from the end of the string
: rfindchar ( str len char -- offs true | false )
   swap 1 - 0 swap do
      over i + c@
      over dup bl = if <= else = then if
         2drop i dup dup leave
      then
   -1 +loop =
;
\ reverse split -- split at the last occurrence of char
: rsplit ( str len char -- left len right len )
  >r 2dup r> rfindchar IF >r over r@ 2swap r> 1+ /string ELSE 0 0 THEN ;

: left-parse-string ( str len char -- R-str R-len L-str L-len )
  split 2swap ;
: replace-char ( str len chout chin -- )
  >r -rot BEGIN 2dup 4 pick findchar WHILE tuck - -rot + r@ over c! swap REPEAT
  r> 2drop 2drop
;
\ Duplicate string and replace \ with /
: \-to-/ ( str len -- str' len ) strdup 2dup [char] \ [char] / replace-char ;

: isdigit ( char -- true | false )
   30 39 between
;

: ishexdigit ( char -- true | false )
   30 39 between 41 46 between OR 61 66 between OR
;

\ Variant of $number that defaults to decimal unless "0x" is
\ a prefix
: $dh-number ( addr len -- true | number false )
   base @ >r
   decimal
   dup 2 > IF
       over dup c@ [char] 0 =
       over 1 + c@ 20 or [char] x =
       AND IF hex 2 + swap 2 - rot THEN drop
   THEN
   $number
   r> base !
;

: //  dup >r 1- + r> / ; \ division, round up

: c@+ ( adr -- c adr' )  dup c@ swap char+ ;
: 2c@ ( adr -- c1 c2 )  c@+ c@ ;
: 4c@ ( adr -- c1 c2 c3 c4 )  c@+ c@+ c@+ c@ ;
: 8c@ ( adr -- c1 c2 c3 c4 c5 c6 c7 c8 )  c@+ c@+ c@+ c@+ c@+ c@+ c@+ c@ ;


: 4dup  ( n1 n2 n3 n4 -- n1 n2 n3 n4 n1 n2 n3 n4 )  2over 2over ;
: 4drop  ( n1 n2 n3 n4 -- )  2drop 2drop ;

\ yes sometimes even something like this is needed
: 5dup  ( 1 2 3 4 5 -- 1 2 3 4 5 1 2 3 4 5 )
   4 pick 4 pick 4 pick 4 pick 4 pick ;
: 5drop 4drop drop ;
: 5nip
  nip nip nip nip nip ;

: 6dup  ( 1 2 3 4 5 6 -- 1 2 3 4 5 6 1 2 3 4 5 6 )
   5 pick 5 pick 5 pick 5 pick 5 pick 5 pick ;

\ convert a 32 bit signed into a 64 signed
\ ( propagate bit 31 to all bits 32:63 )
: signed ( n1 -- n2 ) dup 80000000 and IF FFFFFFFF00000000 or THEN ;

: <l@ ( addr -- x ) l@ signed ;

: -leading  BEGIN dup WHILE over c@ bl <= WHILE 1 /string REPEAT THEN ;
: (parse-line)  skipws 0 parse ;


\ Append two character to hex byte, if possible

: hex-byte ( char0 char1 -- value true|false )
   10 digit IF
      swap 10 digit IF
	 4 lshift or true EXIT
      ELSE
	 2drop 0
      THEN
   ELSE
      drop
   THEN
   false EXIT
;

\ Parse hex string within brackets

: parse-hexstring ( dst-adr -- dst-adr' )
   [char] ) parse cr                 ( dst-adr str len )
   bounds ?DO                        ( dst-adr )
      i c@ i 1+ c@ hex-byte IF       ( dst-adr hex-byte )
	 >r dup r> swap c! 1+ 2      ( dst-adr+1 2 )
      ELSE
	 drop 1                      ( dst-adr 1 )
      THEN
   +LOOP
;

\ Add special character to string

: add-specialchar ( dst-adr special -- dst-adr' )
   over c! 1+                        ( dst-adr' )
   1 >in +!                          \ advance input-index
;

\ Parse up to next "

: parse-" ( dst-adr -- dst-adr' )
   [char] " parse dup 3 pick + >r    ( dst-adr str len R: dst-adr' )
   >r swap r> move r>                ( dst-adr' )
;

: (") ( dst-adr -- dst-adr' )
   begin                             ( dst-adr )
      parse-"                        ( dst-adr' )
      >in @ dup span @ >= IF         ( dst-adr' >in-@ )
         drop
         EXIT
      THEN

      ib + c@
      CASE
         [char] ( OF parse-hexstring ENDOF
         [char] " OF [char] " add-specialchar ENDOF
         dup      OF EXIT ENDOF
      ENDCASE
   again
;

CREATE "pad 100 allot

\ String with embedded hex strings
\ Example: " ba"( 12 34,4567)ab" -> >x62x61x12x34x45x67x61x62<

: " ( [text<">< >] -- text-str text-len )
   state @ IF                        \ compile sliteral, pstr into dict
      "pad dup (") over -            ( str len )
      ['] sliteral compile, dup c,   ( str len )
      bounds ?DO i c@ c, LOOP
      align ['] count compile,
   ELSE
      pocket dup (") over -          \ Interpretation, put string
   THEN                              \ in temp buffer
; immediate


\ Output the carriage-return character
: (cr carret emit ;


\ Remove command old-name and all subsequent definitions

: $forget ( str len -- )
   2dup last @            ( str len str len last-bc )
   BEGIN
      dup >r             ( str len str len last-bc R: last-bc )
      cell+ char+ count  ( str len str len found-str found-len R: last-bc )
      string=ci IF       ( str len R: last-bc )
         r> @ last ! 2drop clean-hash EXIT ( -- )
      THEN
      2dup r> @ dup 0=   ( str len str len next-bc next-bc )
   UNTIL
   drop 2drop 2drop            \ clean hash table
;

: forget ( "old-name<>" -- )
    parse-word $forget
;

#include <search.fs>

\ The following constants are required in some parts
\ of the code, mainly instance variables and see. Having to reverse
\ engineer our own CFAs seems somewhat weird, but we gained a bit speed.

\ Each colon definition is surrounded by colon and semicolon
\ constant below contain address of their xt

: (function) ;
defer (defer)
0 value (value)
0 constant (constant)
variable (variable)
create (create)
alias (alias) (function)
cell buffer: (buffer:)

' (function) @        \ ( <colon> )
' (function) cell + @ \ ( ... <semicolon> )
' (defer) @           \ ( ... <defer> )
' (value) @           \ ( ... <value> )
' (constant) @	      \ ( ... <constant> )
' (variable) @        \ ( ... <variable> )
' (create) @          \ ( ... <create> )
' (alias) @           \ ( ... <alias> )
' (buffer:) @         \ ( ... <buffer:> )

\ now clean up the test functions
forget (function)

\ and remember the constants
constant <buffer:>
constant <alias>
constant <create>
constant <variable>
constant <constant>
constant <value>
constant <defer>
constant <semicolon>
constant <colon>

' lit      constant <lit>
' sliteral constant <sliteral>
' 0branch  constant <0branch>
' branch   constant <branch>
' doloop   constant <doloop>
' dotick   constant <dotick>
' doto     constant <doto>
' do?do    constant <do?do>
' do+loop  constant <do+loop>
' do       constant <do>
' exit     constant <exit>
' doleave  constant <doleave>
' do?leave  constant <do?leave>


\ provide the memory management words
\ #include <claim.fs>
\ #include "memory.fs"
#include <alloc-mem.fs>

#include <node.fs>

: find-substr ( basestr-ptr basestr-len substr-ptr substr-len -- pos )
  \ if substr-len == 0 ?
  dup 0 = IF
    \ return 0
    2drop 2drop 0 exit THEN
  \ if substr-len <= basestr-len ?
  dup 3 pick <= IF
    \ run J from 0 to "basestr-len"-"substr-len" and I from 0 to "substr-len"-1
    2 pick over - 1+ 0 DO dup 0 DO
      \ substr-ptr[i] == basestr-ptr[j+i] ?
      over i + c@ 4 pick j + i + c@ = IF
        \ (I+1) == substr-len ?
        dup i 1+ = IF
          \ return J
          2drop 2drop j unloop unloop exit THEN
      ELSE leave THEN
    LOOP LOOP
  THEN
  \ if there is no match then exit with basestr-len as return value
  2drop nip
;

: find-isubstr ( basestr-ptr basestr-len substr-ptr substr-len -- pos )
  \ if substr-len == 0 ?
  dup 0 = IF
    \ return 0
    2drop 2drop 0 exit THEN
  \ if substr-len <= basestr-len ?
  dup 3 pick <= IF
    \ run J from 0 to "basestr-len"-"substr-len" and I from 0 to "substr-len"-1
    2 pick over - 1+ 0 DO dup 0 DO
      \ substr-ptr[i] == basestr-ptr[j+i] ?
      over i + c@ lcc 4 pick j + i + c@ lcc = IF
        \ (I+1) == substr-len ?
        dup i 1+ = IF
          \ return J
          2drop 2drop j unloop unloop exit THEN
      ELSE leave THEN
    LOOP LOOP
  THEN
  \ if there is no match then exit with basestr-len as return value
  2drop nip
;

: find-nextline ( str-ptr str-len -- pos )
  \ run I from 0 to "str-len"-1 and check str-ptr[i]
  dup 0 ?DO over i + c@ CASE
    \ 0x0a (=LF) found ?
    0a OF
      \ if current cursor is at end position (I == "str-len"-1) ?
      dup 1- i = IF
        \ return I+1
        2drop i 1+ unloop exit THEN
        \ if str-ptr[I+1] == 0x0d (=CR) ?
      over i 1+ + c@ 0d = IF
        \ return I+2
        2drop i 2+ ELSE
        \ else return I+1
        2drop i 1+ THEN
      unloop exit
    ENDOF
    \ 0x0d (=CR) found ?
    0d OF
      \ if current cursor is at end position (I == "str-len"-1) ?
      dup 1- i = IF
        \ return I+1
        2drop i 1+ unloop exit THEN
      \ str-ptr[I+1] == 0x0a (=LF) ?
      over i 1+ + c@ 0a = IF
        \ return I+2
        2drop i 2+ ELSE
        \ return I+1
        2drop i 1+ THEN
      unloop exit
    ENDOF
  ENDCASE LOOP nip
;

: string-at ( str1-ptr str1-len pos -- str2-ptr str2-len )
  -rot 2 pick - -rot swap chars + swap
;

\ appends the string beginning at addr2 to the end of the string
\ beginning at addr1
\ !!! THERE MUST BE SUFFICIENT MEMORY RESERVED FOR THE STRING !!!
\ !!!        BEGINNING AT ADDR1 (cp. 'strcat' in 'C' )        !!!

: string-cat ( addr1 len1 addr2 len2 -- addr1 len1+len2 )
  \ len1 := len1+len2
  rot dup >r over + -rot
  ( addr1 len1+len2 dest-ptr src-ptr len2 )
  3 pick r> chars + -rot
  ( ... dest-ptr src-ptr )
  0 ?DO
    2dup c@ swap c!
    char+ swap char+ swap
  LOOP 2drop
;

\ appends a character to the end of the string beginning at addr
\ !!! THERE MUST BE SUFFICIENT MEMORY RESERVED FOR THE STRING !!!
\ !!!        BEGINNING AT ADDR1 (cp. 'strcat' in 'C' )        !!!

: char-cat ( addr len character -- addr len+1 )
  -rot 2dup >r >r 1+ rot r> r> chars + c!
;

\ Returns true if source and destination overlap
: overlap ( src dest size -- true|false )
	3dup over + within IF 3drop true ELSE rot tuck + within THEN
;

: parse-2int ( str len -- val.lo val.hi )
\ ." parse-2int ( " 2dup swap . . ." -- "
	[char] , split ?dup IF eval ELSE drop 0 THEN
	-rot ?dup IF eval ELSE drop 0 THEN
\ 2dup swap . . ." )" cr
;

\ peek/poke minimal implementation, just to support FCode drivers
\ Any implmentation with full error detection will be platform specific
: cpeek ( addr -- false | byte true ) c@ true ;
: cpoke ( byte addr -- success? ) c! true ;
: wpeek ( addr -- false | word true ) w@ true ;
: wpoke ( word addr -- success? ) w! true ;
: lpeek ( addr -- false | lword true ) l@ true ;
: lpoke ( lword addr -- success? ) l! true ;

defer reboot ( -- )
defer halt ( -- )
defer disable-watchdog ( -- )
defer reset-watchdog ( -- )
defer set-watchdog ( +n -- )
defer set-led ( type instance state -- status )
defer get-flashside ( -- side )
defer set-flashside ( side -- status )
defer read-bootlist ( -- )
defer furnish-boot-file ( -- adr len )
defer set-boot-file ( adr len -- )
defer mfg-mode? ( -- flag )
defer of-prompt? ( -- flag )
defer debug-boot? ( -- flag )
defer bmc-version ( -- adr len )
defer cursor-on ( -- )
defer cursor-off ( -- )

: nop-reboot ( -- ) ." reboot not available" abort ;
: nop-halt ( -- ) ." halt not available" abort ;
: nop-disable-watchdog ( -- )  ;
: nop-reset-watchdog ( -- )  ;
: nop-set-watchdog ( +n -- ) drop ;
: nop-set-led ( type instance state -- status ) drop drop drop ;
: nop-get-flashside ( -- side ) ." Cannot get flashside" cr ABORT ;
: nop-set-flashside ( side -- status ) ." Cannot set flashside" cr ABORT ;
: nop-read-bootlist ( -- ) ;
: nop-furnish-bootfile ( -- adr len ) s" net:" ;
: nop-set-boot-file ( adr len -- ) 2drop ;
: nop-mfg-mode? ( -- flag ) false ;
: nop-of-prompt? ( -- flag ) false ;
: nop-debug-boot? ( -- flag ) false ;
: nop-bmc-version ( -- adr len ) s" XXXXX" ;
: nop-cursor-on ( -- ) ;
: nop-cursor-off ( -- ) ;

' nop-reboot to reboot
' nop-halt to halt
' nop-disable-watchdog to disable-watchdog
' nop-reset-watchdog   to reset-watchdog
' nop-set-watchdog     to set-watchdog
' nop-set-led          to set-led
' nop-get-flashside    to get-flashside
' nop-set-flashside    to set-flashside
' nop-read-bootlist    to read-bootlist
' nop-furnish-bootfile to furnish-boot-file
' nop-set-boot-file    to set-boot-file
' nop-mfg-mode?        to mfg-mode?
' nop-of-prompt?       to of-prompt?
' nop-debug-boot?      to debug-boot?
' nop-bmc-version      to bmc-version
' nop-cursor-on        to cursor-on
' nop-cursor-off       to cursor-off

: reset-all reboot ;

\ load-base is an env. variable now, but it can
\ be overriden temporarily provided users use
\ get-load-base rather than load-base directly
\
\ default-load-base is set here and can be
\ overriden by the board code. It will be used
\ to set the default value of the envvar "load-base"
\ when booting without a valid nvram

10000000 VALUE default-load-base
2000000 VALUE flash-load-base
0 VALUE load-base-override

: get-load-base
  load-base-override 0<> IF load-base-override ELSE
    " load-base" evaluate 
  THEN
;

\ provide first level debug support
#include "debug.fs"
\ provide 7.5.3.1 Dictionary search
#include "dictionary.fs"
\ provide a simple run time preprocessor
#include <preprocessor.fs>

: $dnumber base @ >r decimal $number r> base ! ;
: (.d) base @ >r decimal (.) r> base ! ;

\ IP address conversion

: (ipaddr) ( "a.b.c.d" -- FALSE | n1 n2 n3 n4 TRUE )
   base @ >r decimal
   over s" 000.000.000.000" comp 0= IF 2drop false r> base ! EXIT THEN
   [char] . left-parse-string $number IF 2drop false r> base ! EXIT THEN -rot
   [char] . left-parse-string $number IF 2drop false r> base ! EXIT THEN -rot
   [char] . left-parse-string $number IF 2drop false r> base ! EXIT THEN -rot
   $number IF false r> base ! EXIT THEN
   true r> base !
;

: (ipformat)  ( n1 n2 n3 n4 -- str len )
   base @ >r decimal
   0 <# # # # [char] . hold drop # # # [char] . hold
   drop # # # [char] . hold drop # # #s #>
   r> base !
;

: ipformat  ( n1 n2 n3 n4 -- ) (ipformat) type ;


