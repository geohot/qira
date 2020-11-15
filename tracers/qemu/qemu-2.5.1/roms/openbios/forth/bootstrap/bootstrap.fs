\ tag: bootstrap of basic forth words
\ 
\ Copyright (C) 2003-2005 Stefan Reinauer, Patrick Mauritz
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

\ 
\ this file contains almost all forth words described
\ by the open firmware user interface. Some more complex
\ parts are found in seperate files (memory management,
\ vocabulary support)
\ 

\ 
\ often used constants (reduces dictionary size)
\ 

1 constant 1
2 constant 2
3 constant 3
-1 constant -1
0 constant 0

0 value my-self

\ 
\ 7.3.5.1 Numeric-base control
\ 

: decimal 10 base ! ;
: hex 16 base ! ;
: octal 8 base ! ;
hex

\ 
\ vocabulary words
\ 

variable current forth-last current !

: last 
  current @ 
  ;

variable #order 0 #order !

defer context
0 value vocabularies?

defer locals-end
0 value locals-dict
variable locals-dict-buf

\ 
\ 7.3.7 Flag constants
\ 

1 1 = constant true
0 1 = constant false

\ 
\ 7.3.9.2.2 Immediate words (part 1)
\ 

: (immediate) ( xt -- )
  1 - dup c@ 1 or swap c!
  ;

: (compile-only)
  1 - dup c@ 2 or swap c!
  ;

: immediate 
  last @ (immediate) 
  ;
  
: compile-only 
  last @ (compile-only) 
  ;

: flags? ( xt -- flags )
  /n /c + - c@ 7f and
  ;

: immediate? ( xt -- true|false )
  flags? 1 and 1 =
  ;

: compile-only? ( xt -- true|false )
  flags? 2 and 2 =
  ;

: [  0 state ! ; compile-only
: ] -1 state ! ; 



\ 
\ 7.3.9.2.1 Data space allocation
\ 

: allot here + here! ;
: ,  here /n allot ! ;
: c, here /c allot c! ;

: align
  /n here /n 1 - and -   \ how many bytes to next alignment
  /n 1 - and allot       \ mask out everything that is bigger 
  ;                      \ than cellsize-1

: null-align
  here dup align here swap - 0 fill 
  ;

: w, 
  here 1 and allot       \ if here is not even, we have to align.
  here /w allot w! 
  ;

: l, 
  /l here /l 1 - and -   \ same as in align, with /l
  /l 1 - and             \ if it's /l we are already aligned.
  allot
  here /l allot l! 
  ;


\ 
\ 7.3.6 comparison operators (part 1)
\ 

: <> = invert ;


\ 
\ 7.3.9.2.4 Miscellaneous dictionary (part 1)
\ 

: (to) ( xt-new xt-defer -- )
  /n + !
  ;

: >body ( xt -- a-addr )  /n 1 lshift + ;
: body> ( a-addr -- xt )  /n 1 lshift - ;

: reveal latest @ last ! ;
: recursive reveal ; immediate
: recurse latest @ /n +  , ; immediate

: noop ;

defer environment?
: no-environment?
  2drop false 
  ;

['] no-environment? ['] environment? (to)


\ 
\ 7.3.8.1 Conditional branches
\ 

\ A control stack entry is implemented using 2 data stack items
\ of the form ( addr type ). type can be one of the
\ following:
\   0 - orig
\   1 - dest
\   2 - do-sys

: resolve-orig here nip over /n + - swap ! ;
: (if) ['] do?branch , here 0 0 , ; compile-only
: (then) resolve-orig ; compile-only

variable tmp-comp-depth -1 tmp-comp-depth !
variable tmp-comp-buf 0 tmp-comp-buf !

: setup-tmp-comp ( -- )
  state @ 0 = (if)
    here tmp-comp-buf @ here! ,     \ save here and switch to tmp directory
    1 ,                              \ DOCOL
    depth tmp-comp-depth !          \ save control depth
    ]
  (then)
;

: execute-tmp-comp ( -- )
  depth tmp-comp-depth @ =
  (if)
    -1 tmp-comp-depth !
    ['] (semis) ,
    tmp-comp-buf @
    dup @ here!
    0 state !
    /n + execute
  (then)
;

: if setup-tmp-comp ['] do?branch , here 0 0 , ; immediate
: then resolve-orig execute-tmp-comp ; compile-only
: else ['] dobranch , here 0 0 , 2swap resolve-orig ; compile-only

\ 
\ 7.3.8.3 Conditional loops
\ 

\ some dummy words for see
: (begin) ;
: (again) ;
: (until) ;
: (while) ;
: (repeat) ;

\ resolve-dest requires a loop...
: (resolve-dest) here /n + nip - , ;
: (resolve-begin) setup-tmp-comp ['] (begin) , here 1 ; immediate
: (resolve-until) ['] (until) , ['] do?branch , (resolve-dest) execute-tmp-comp ; compile-only

: resolve-dest ( dest origN ... orig )
  2 >r
  (resolve-begin)
    \ Find topmost control stack entry with a type of 1 (dest)
    r> dup dup pick 1 = if
      \ Move it to the top
      roll
      swap 1 - roll
      \ Resolve it
      (resolve-dest)
      1		\ force exit
    else
      drop
      2 + >r
      0
    then
  (resolve-until)
;

: begin
  setup-tmp-comp
  ['] (begin) , 
  here
  1
  ; immediate

: again
  ['] (again) ,
  ['] dobranch , 
  resolve-dest
  execute-tmp-comp
  ; compile-only

: until
  ['] (until) ,
  ['] do?branch , 
  resolve-dest
  execute-tmp-comp
  ; compile-only

: while
  setup-tmp-comp
  ['] (while) ,
  ['] do?branch , 
  here 0 0 , 2swap  
  ; immediate

: repeat
  ['] (repeat) ,
  ['] dobranch , 
  resolve-dest resolve-orig
  execute-tmp-comp
  ; compile-only


\ 
\ 7.3.8.4 Counted loops
\ 

variable leaves 0 leaves !

: resolve-loop
  leaves @
  begin
    ?dup 
  while 
    dup @               \ leaves -- leaves *leaves )
    swap                \ -- *leaves leaves )
    here over -         \ -- *leaves leaves here-leaves
    swap !              \ -- *leaves
  repeat
  here nip - , 
  leaves !
  ;

: do
  setup-tmp-comp
  leaves @
  here 2
  ['] (do) , 
  0 leaves !
  ; immediate

: ?do
  setup-tmp-comp
  leaves @ 
  ['] (?do) ,
  here 2
  here leaves !
  0 ,
  ; immediate

: loop
  ['] (loop) ,
  resolve-loop
  execute-tmp-comp
  ; immediate 

: +loop
  ['] (+loop) ,
  resolve-loop
  execute-tmp-comp
  ; immediate


\ Using primitive versions of i and j
\ speeds up loops by 300%
\ : i r> r@ swap >r ;
\ : j r> r> r> r@ -rot >r >r swap >r ;

: unloop r> r> r> 2drop >r ;

: leave 
  ['] unloop , 
  ['] dobranch , 
  leaves @ 
  here leaves !  
  , 
  ; immediate

: ?leave if leave then ;

\ 
\ 7.3.8.2  Case statement
\ 
 
: case
  setup-tmp-comp
  0
; immediate

: endcase
  ['] drop , 
  0 ?do
    ['] then execute
  loop
  execute-tmp-comp
; immediate

: of
  1 + >r 
  ['] over , 
  ['] = , 
  ['] if execute 
  ['] drop , 
  r> 
  ; immediate

: endof
  >r 
  ['] else execute 
  r> 
  ; immediate

\ 
\ 7.3.8.5    Other control flow commands
\ 

: exit r> drop ;


\ 
\ 7.3.4.3 ASCII constants (part 1)
\ 

20 constant bl
07 constant bell
08 constant bs
0d constant carret
0a constant linefeed


\ 
\ 7.3.1.1 - stack duplication
\ 
: tuck swap over ;
: 3dup 2 pick 2 pick 2 pick ;

\ 
\ 7.3.1.2 - stack removal
\ 
: clear 0 depth! ;
: 3drop 2drop drop ;

\ 
\ 7.3.1.3 - stack rearrangement
\ 

: 2rot >r >r 2swap r> r> 2swap ;

\
\ 7.3.1.4 - return stack
\

\ Note: these words are not part of the official OF specification, however
\ they are part of the ANSI DPANS94 core extensions (see section 6.2) and
\ so this seems an appropriate place for them.
: 2>r r> -rot swap >r >r >r ;
: 2r> r> r> r> rot >r swap ;
: 2r@ r> r> r> 2dup >r >r rot >r swap ;

\ 
\ 7.3.2.1 - single precision integer arithmetic (part 1)
\ 

: u/mod 0 swap mu/mod drop ;
: 1+ 1 + ;
: 1- 1 - ;
: 2+ 2 + ;
: 2- 2 - ;
: even 1+ -2 and ;
: bounds over + swap ;

\ 
\ 7.3.2.2 bitwise logical operators
\ 
: << lshift ;
: >> rshift ;
: 2* 1 lshift ;
: u2/ 1 rshift ;
: 2/ 1 >>a ;
: not invert ;

\ 
\ 7.3.2.3 double number arithmetic
\ 

: s>d      dup 0 < ; 
: dnegate  0 0 2swap d- ;
: dabs     dup 0 < if dnegate then ;
: um/mod   mu/mod drop ;

\ symmetric division
: sm/rem  ( d n -- rem quot )
  over >r >r dabs r@ abs um/mod r> 0 < 
  if 
    negate 
  then 
  r> 0 < if 
    negate swap negate swap
  then
  ;

\ floored division
: fm/mod ( d n -- rem quot ) 
  dup >r 2dup xor 0 < >r sm/rem over 0 <> r> and if 
    1 - swap r> + swap exit 
  then
  r> drop
  ;

\ 
\ 7.3.2.1 - single precision integer arithmetic (part 2)
\ 

: */mod ( n1 n2 n3 -- quot rem ) >r m* r> fm/mod  ;
: */ ( n1 n2 n3 -- n1*n2/n3 ) */mod nip ;
: /mod >r s>d r> fm/mod ;
: mod /mod drop ;
: / /mod nip ;


\ 
\ 7.3.2.4 Data type conversion
\ 

: lwsplit ( quad -- w.lo w.hi )
  dup ffff and swap 10 rshift ffff and
;

: wbsplit ( word -- b.lo b.hi )
  dup ff and swap 8 rshift ff and
;

: lbsplit ( quad -- b.lo b2 b3 b.hi )
  lwsplit swap wbsplit rot wbsplit
;

: bwjoin ( b.lo b.hi -- word )
  ff and 8 lshift swap ff and or
;

: wljoin ( w.lo w.hi -- quad )
  ffff and 10 lshift swap ffff and or
;

: bljoin ( b.lo b2 b3 b.hi -- quad )
  bwjoin -rot bwjoin swap wljoin
;

: wbflip ( word -- word ) \ flips bytes in a word
  dup 8 rshift ff and swap ff and bwjoin
;

: lwflip ( q1 -- q2 ) 
  dup 10 rshift ffff and swap ffff and wljoin
;

: lbflip ( q1 -- q2 )
  dup 10 rshift ffff and wbflip swap ffff and wbflip wljoin
;

\ 
\ 7.3.2.5 address arithmetic
\ 

: /c* /c * ;
: /w* /w * ;
: /l* /l * ;
: /n* /n * ;
: ca+ /c* + ;
: wa+ /w* + ;
: la+ /l* + ;
: na+ /n* + ;
: ca1+ /c + ;
: wa1+ /w + ;
: la1+ /l + ;
: na1+ /n + ;
: aligned /n 1- + /n negate and ;
: char+ ca1+ ;
: cell+ na1+ ;
: chars /c* ;
: cells /n* ;
/n constant cell

\ 
\ 7.3.6 Comparison operators
\ 

: <= > not ;
: >= < not ;
: 0= 0 = ;
: 0<= 0 <= ;
: 0< 0 < ;
: 0<> 0 <> ;
: 0> 0 > ;
: 0>=  0 >= ;
: u<= u> not ;
: u>= u< not ;
: within  >r over > swap r> >= or not ;
: between 1 + within ;

\ 
\ 7.3.3.1 Memory access
\ 

: 2@ dup cell+ @ swap @  ;
: 2! dup >r ! r> cell+ ! ;

: <w@ w@ dup 8000 >= if 10000 - then ;

: comp ( str1 str2 len -- 0|1|-1 )
  >r 0 -rot r>
  bounds ?do
    dup c@ i c@ - dup if
      < if 1 else -1 then swap leave
    then 
    drop ca1+
  loop
  drop
;

\ compare two string

: $= ( str1 len1 str2 len2 -- true|false )
    rot ( str1 str2 len2 len1 )
    over ( str1 str2 len2 len1 len2 )  
    <> if ( str1 str2 len2 )
        3drop
        false
    else ( str1 str2 len2 )
        comp
	0=
    then
;

\ : +! tuck @ + swap ! ;
: off false swap ! ;
: on true swap ! ;
: blank bl fill ;
: erase 0 fill ;
: wbflips ( waddr len -- )
  bounds do i w@ wbflip i w! /w +loop
;

: lwflips ( qaddr len -- )
  bounds do i l@ lwflip i l! /l +loop
;

: lbflips ( qaddr len -- )
  bounds do i l@ lbflip i l! /l +loop
;


\ 
\ 7.3.8.6    Error handling (part 1)
\ 

variable catchframe
0 catchframe !

: catch
  my-self >r
  depth >r
  catchframe @ >r
  rdepth catchframe !
  execute
  r> catchframe !
  r> r> 2drop 0
  ;

: throw
  ?dup if
    catchframe @ rdepth!
    r> catchframe !
    r> swap >r depth!
    drop r>
    r> ['] my-self (to)
  then
  ;

\ 
\ 7.3.3.2 memory allocation
\ 

include memory.fs


\ 
\ 7.3.4.4 Console output (part 1)
\ 

defer emit

: type bounds ?do i c@ emit loop ;

\ this one obviously only works when called 
\ with a forth string as count fetches addr-1.
\ openfirmware has no such req. therefore it has to go:

\ : type 0 do count emit loop drop ;

: debug-type bounds ?do i c@ (emit) loop ;

\ 
\ 7.3.4.1 Text Input
\ 

0 value source-id 
0 value ib
variable #ib 0 #ib !
variable >in 0 >in !

: source ( -- addr len )
  ib #ib @
  ;

: /string  ( c-addr1 u1 n -- c-addr2 u2 )
   tuck - -rot + swap 
; 


\ 
\ pockets implementation for 7.3.4.1

100 constant pocketsize
4   constant numpockets
variable pockets 0 pockets !
variable whichpocket 0 whichpocket !

\ allocate 4 pockets to begin with
: init-pockets     ( -- )
  pocketsize numpockets * alloc-mem pockets !
  ;

: pocket ( ?? -- ?? )
  pocketsize whichpocket @ *
  pockets @ +
  whichpocket @ 1 + numpockets mod
  whichpocket !
  ;

\ span variable from 7.3.4.2
variable span 0 span !

\ if char is bl then any control character is matched
: findchar ( str len char -- offs true | false )
  swap 0 do
    over i + c@
    over dup bl = if <= else = then if
      2drop i dup dup leave
      \ i nip nip true exit \ replaces above
    then
  loop
  =
  \ drop drop false
  ;

: parse ( delim  text<delim>  -- str len )
  >r              \ save delimiter
  ib >in @ +
  span @ >in @ -  \ ib+offs len-offset.
  dup 0 < if      \ if we are already at the end of the string, return an empty string
    + 0	          \ move to end of input string
    r> drop
    exit
  then
  2dup r>         \ ib+offs len-offset ib+offs len-offset delim
  findchar if     \ look for the delimiter. 
    nip dup 1+
  else
     dup
  then
  >in +!
  \ dup -1 = if drop 0 then \ workaround for negative length
  ;

: skipws ( -- )
  ib span @        ( -- ib recvchars )
  begin
    dup >in @ > if    ( -- recvchars>offs )
      over >in @ +
      c@ bl <=
    else
      false
    then
  while
      1 >in +!
  repeat
  2drop
  ;

: parse-word (  < >text< >  -- str len )
  skipws bl parse
  ;

: word ( delim  <delims>text<delim>  -- pstr )
  pocket >r parse dup r@ c! bounds r> dup 2swap
  do
    char+ i c@ over c!
  loop
  drop
  ;

: ( 29 parse 2drop ; immediate
: \ span @ >in !   ; immediate



\ 
\ 7.3.4.7 String literals
\ 

: ",
  bounds ?do
    i c@ c,
  loop
  ;

: (")  ( -- addr len )
  r> dup 
  2 cells +                   ( r-addr addr )
  over cell+ @                ( r-addr addr len )
  rot over + aligned cell+ >r ( addr len R: r-addr )
  ;
 
: handle-text ( temp-addr len -- addr len )
  state @ if
    ['] (") , dup , ", null-align
  else
    pocket swap
    dup >r
    0 ?do
      over i + c@ over i + c!
    loop
    nip r>
  then
  ;

: s"
  22 parse handle-text
  ; immediate



\ 
\ 7.3.4.4 Console output (part 2)
\ 

: ."
  22 parse handle-text
  ['] type
  state @ if
    ,
  else
    execute
  then
  ; immediate

: .(
  29 parse handle-text
  ['] type
  state @ if
    ,
  else
    execute
  then
  ; immediate



\ 
\ 7.3.4.8 String manipulation
\ 

: count ( pstr -- str len ) 1+ dup 1- c@ ;

: pack  ( str len addr -- pstr )
  2dup c!     \ store len
  1+ swap 0 ?do
    over i + c@ over i + c!
  loop nip 1-
  ;

: lcc   ( char1 -- char2 ) dup 41 5a between if 20 + then ;
: upc   ( char1 -- char2 ) dup 61 7a between if 20 - then ;

: -trailing ( str len1 -- str len2 )
  begin 
    dup 0<> if  \ len != 0 ?
      2dup 1- + 
      c@ bl =
    else 
      false 
    then
  while
    1-
  repeat
  ;


\ 
\ 7.3.4.5   Output formatting
\ 

: cr linefeed emit ;
: debug-cr linefeed (emit) ;
: (cr carret emit ;
: space bl emit ;
: spaces 0 ?do space loop ;
variable #line 0 #line !
variable #out  0 #out  !


\ 
\ 7.3.9.2.3 Dictionary search
\ 

\ helper functions

: lfa2name ( lfa -- name len )
  1-                   \ skip flag byte
  begin                \ skip 0 padding 
    1- dup c@ ?dup 
  until
  7f and               \ clear high bit in length

  tuck - swap          ( ptr-to-len len - name len )
  ;

: comp-nocase ( str1 str2 len -- true|false )
  0 do
    2dup i + c@ upc    ( str1 str2 byteX )
    swap i + c@ upc ( str1 str2 byte1 byte2 )
    <> if
      0 leave
    then
  loop
  if -1 else drop 0 then
  swap drop
  ;

: comp-word ( b-str len lfa -- true | false )
  lfa2name        ( str len str len -- )
  >r swap r>      ( str str len len )
  over = if       ( str str len )
    comp-nocase
  else
    drop drop drop false   \ if len does not match, string does not match
  then
;

\ $find is an fcode word, but we place it here since we use it for find.

: find-wordlist ( name-str name-len last -- xt true | name-str name-len false )

  @ >r

  begin
    2dup r@ dup if comp-word dup false = then
  while
    r> @ >r drop
  repeat

  r@ if \ successful?
    -rot 2drop r> cell+ swap
  else
    r> drop drop drop false
  then

  ;

: $find ( name-str name-len -- xt true | name-str name-len false )
  locals-dict 0<> if
    locals-dict-buf @ find-wordlist ?dup if
      exit
    then
  then
  vocabularies? if
    #order @ 0 ?do
      i cells context + @
      find-wordlist
      ?dup if
        unloop exit
      then
    loop
    false
  else
    forth-last find-wordlist
  then
  ;

\ look up a word in the current wordlist
: $find1 ( name-str name-len -- xt true | name-str name-len false )
  vocabularies? if
    current @
  else
    forth-last
  then
  find-wordlist
  ;

  
: '
  parse-word $find 0= if 
    type 3a emit -13 throw
  then
  ;

: ['] 
  parse-word $find 0= if
    type 3a emit -13 throw
  then 
  state @ if
    ['] (lit) , , 
  then
  ; immediate

: find ( pstr -- xt n | pstr false )
  dup count $find           \  pstr xt true | pstr name-str name-len false
  if
    nip true
    over immediate? if
      negate                \ immediate returns 1
    then
  else
    2drop false
  then
  ;


\ 
\ 7.3.9.2.2 Immediate words (part 2)
\ 

: literal ['] (lit) , , ; immediate
: compile, , ; immediate
: compile r> cell+ dup @ , >r ;
: [compile] ['] ' execute , ; immediate

: postpone
  parse-word $find if
    dup immediate? not if
      ['] (lit) , , ['] ,
    then
    ,
  else
    s" undefined word " type type cr
  then
  ; immediate


\ 
\ 7.3.9.2.4 Miscellaneous dictionary (part 2)
\ 

variable #instance

: instance ( -- )
  true #instance !
;

: #instance-base
  my-self dup if @ then
;

: #instance-offs
  my-self dup if na1+ then
;

\ the following instance words are used internally
\ to implement variable instantiation.

: instance-cfa? ( cfa -- true | false )
  b e within                              \ b,c and d are instance defining words
;

: behavior ( xt-defer -- xt )
  dup @ instance-cfa? if
    #instance-base ?dup if
      swap na1+ @ + @
    else
      3 /n* + @
    then
  else
    na1+ @
  then
;

: (ito) ( xt-new xt-defer -- )
  #instance-base ?dup if
    swap na1+ @ + !
  else
    3 /n* + !
  then
;
  
: (to-xt) ( xt -- )  
  dup @ instance-cfa?
  state @ if
    swap ['] (lit) , , if ['] (ito) else ['] (to) then ,
  else
    if (ito) else /n + ! then
  then
;

: to
  ['] ' execute
  (to-xt)
  ; immediate
  
: is ( xt "wordname<>" -- )
  parse-word $find if
    (to)
  else
    s" could not find " type type
  then
  ;

\ 
\ 7.3.4.2 Console Input
\ 

defer key?
defer key

: accept ( addr len -- len2 )
  tuck 0 do
    key
    dup linefeed = if
      space drop drop drop i 0 leave
    then
    dup emit over c! 1 +
  loop
  drop ( cr )
  ;

: expect ( addr len -- )
  accept span !
  ;


\ 
\ 7.3.4.3 ASCII constants (part 2)
\ 

: handle-lit
  state @ if
    2 = if
      ['] (lit) ,  ,
    then
    ['] (lit) ,  ,
  else
    drop
  then
  ;

: char
  parse-word 0<> if c@ else s" Unexpected EOL." type cr then ;
  ;

: ascii  char 1 handle-lit ; immediate
: [char] char 1 handle-lit ; immediate

: control   
  char bl 1- and 1 handle-lit 
; immediate



\ 
\ 7.3.8.6    Error handling (part 2)
\ 

: abort 
  -1 throw
  ;

: abort"
  ['] if execute
  22 parse handle-text 
  ['] type , 
  ['] (lit) , 
  -2 , 
  ['] throw ,
  ['] then execute
  ; compile-only 

\ 
\ 7.5.3.1 Dictionary search
\ 

\ this does not belong here, but its nice for testing

: words ( -- )
  last
  begin @ 
    ?dup while
    dup lfa2name

    \ Don't print spaces for headerless words
    dup if
      type space
    else
      type
    then

  repeat
  cr
  ;

\ 
\ 7.3.5.4 Numeric output primitives
\ 

false value capital-hex?

: pad       ( -- addr )      here 100 + aligned ;

: todigit   ( num -- ascii ) 
  dup 9 > if 
    capital-hex? not if
      20 +
    then
    7 + 
  then 
  30 + 
  ;

: <#   pad dup ! ;
: hold pad dup @ 1- tuck swap ! c! ;
: sign 
  0< if 
    2d hold 
  then 
  ;

: #    base @ mu/mod rot todigit hold ;
: #s   begin # 2dup or 0= until ;
: #>   2drop pad dup @ tuck - ;
: (.)  <# dup >r abs 0 #s r> sign #> ;

: u#   base @ u/mod swap todigit hold ;
: u#s  begin u# dup 0= until ;
: u#> 0 #> ;
: (u.) <# u#s u#> ;

\ 
\ 7.3.5.3 Numeric output
\ 

: .    (.) type space ;
: s.   . ;
: u.   (u.) type space ;
: .r   swap (.) rot 2dup < if over - spaces else drop then type ;
: u.r  swap (u.) rot 2dup < if over - spaces else drop then type ;
: .d   base @ swap decimal . base ! ;
: .h   base @ swap hex . base ! ;

: .s 
  3c emit depth dup (.) type 3e emit space
  0 
  ?do
    depth i - 1- pick .
  loop 
  cr
  ;

\ 
\ 7.3.5.2 Numeric input
\ 

: digit ( char base -- n true | char false )
  swap dup upc dup 
  41 5a ( A - Z ) between if
    7 -
  else
    dup 39 > if \ protect from : and ;
      -rot 2drop false exit
    then
  then
  
  30 ( number 0 ) - rot over swap 0 swap within  if
    nip true
  else
    drop false
  then  
  ;

: >number
   begin 
      dup 
   while
      over c@ base @ digit 0= if    
         drop exit 
      then  >r 2swap r> swap base @ um* drop rot base @ um* d+ 2swap 
      1 /string 
   repeat 
   ;

: numdelim?   
   dup 2e = swap 2c = or 
; 


: $dnumber?   
   0 0 2swap dup 0= if    
      2drop 2drop 0 exit 
   then  over c@ 2d = dup >r negate /string begin 
      >number dup 1 > 
   while
      over c@ numdelim? 0= if    
         2drop 2drop r> drop 0 exit 
      then  1 /string 
   repeat if    
      c@ 2e = if    
         true 
      else
         2drop r> drop 0 exit 
      then  
   else
      drop false 
   then  over or if    
      r> if    
         dnegate 
      then  2 
   else
     drop r> if    
         negate 
      then  1 
   then  
; 


: $number (  )
   $dnumber? 
   case
   0 of   true endof
   1 of   false endof
   2 of   drop false endof
   endcase
; 

: d#
  parse-word
  base @ >r

  decimal

  $number if
    s" illegal number" type cr 0
  then
  r> base !
  1 handle-lit
  ; immediate

: h#
  parse-word
  base @ >r

  hex

  $number if
    s" illegal number" type cr 0
  then
  r> base !
  1 handle-lit
  ; immediate

: o#
  parse-word
  base @ >r

  octal

  $number if
    s" illegal number" type cr 0
  then
  r> base !
  1 handle-lit
  ; immediate


\ 
\ 7.3.4.7 String Literals (part 2)
\ 

: "
  pocket dup
  begin
    span @ >in @ > if
      22 parse >r         ( pocket pocket str  R: len )
      over r@ move        \ copy string
      r> +                ( pocket nextdest )
      ib >in @ + c@       ( pocket nextdest nexchar )
      1 >in +!
      28 =                \ is nextchar a parenthesis?
      span @ >in @ >      \ more input?
      and
    else
      false
    then
  while
    29 parse              \ parse everything up to the next ')'
    bounds ?do
      i c@ 10 digit if
        i 1+ c@ 10 digit if
          swap 4 lshift or
        else
          drop
        then
        over c! 1+
        2
      else
        drop 1
      then
    +loop
  repeat
  over -
  handle-text
; immediate


\ 
\ 7.3.3.1 Memory Access (part 2)
\ 

: dump ( addr len -- )
  over + swap
  cr
  do i u. space
    10 0 do
      j i + c@
      dup 10 / todigit emit
      10 mod todigit emit
      space
      i 7 = if space then
    loop
    3 spaces
    10 0 do
      j i + c@
      dup 20 < if drop 2e then \ non-printables as dots?
      emit
    loop
    cr
  10 +loop
;



\ 
\ 7.3.9.1 Defining words
\ 

: header ( name len -- )
  dup if                            \ might be a noname...
    2dup $find1 if
      drop 2dup type s"  isn't unique." type cr
    else
      2drop
    then
  then
  null-align
  dup -rot ", 80 or c,              \ write name and len
  here /n 1- and 0= if 0 c, then    \ pad and space for flags
  null-align
  80 here 1- c!                     \ write flags byte
  here last @ , latest !            \ write backlink and set latest
 ;


: :
  parse-word header
  1 , ]
  ;

: :noname 
  0 0 header 
  here
  1 , ]
  ;

: ;
  locals-dict 0<> if
    0 ['] locals-dict /n + !
    ['] locals-end , 
  then
  ['] (semis) , reveal ['] [ execute
  ; immediate

: constant
  parse-word header
  3 , ,                             \ compile DOCON and value
  reveal
  ;

0 value active-package
: instance, ( size -- )
  \ first word of the device node holds the instance size
  dup active-package @ dup rot + active-package !
  , ,      \ offset size
;

: instance? ( -- flag )
  #instance @ dup if
    false #instance !
  then
;

: value
  parse-word header
  instance? if
    /n b , instance, ,              \ DOIVAL
  else
    3 , ,
  then
  reveal
  ;

: variable
  parse-word header
  instance? if
    /n c , instance, 0 ,
  else
    4 , 0 ,
  then
  reveal
  ;

: $buffer: ( size str len -- where )
  header
  instance? if
    /n over /n 1- and - /n 1- and +     \ align buffer size
    dup c , instance,                   \ DOIVAR
  else
    4 ,
  then
  here swap
  2dup 0 fill                            \ zerofill
  allot
  reveal
;

: buffer: ( size -- )
  parse-word $buffer: drop
;

: (undefined-defer)  ( -- )
  \ XXX: this does not work with behavior ... execute
  r@ 2 cells - lfa2name
  s" undefined defer word " type type cr ;

: (undefined-idefer)  ( -- )
  s" undefined idefer word " type cr ;

: defer  (  new-name< >  -- )
  parse-word header
  instance? if
    2 /n* d , instance,                 \ DOIDEFER
    ['] (undefined-idefer)
  else
    5 ,
    ['] (undefined-defer)
  then
  ,
  ['] (semis) ,
  reveal
  ;

: alias  (  new-name< >old-name< >  -- )
  parse-word
  parse-word $find if
    -rot                     \ move xt behind.
    header
    1 ,                      \ fixme we want our own cfa here.
    ,                        \ compile old name xt
    ['] (semis) ,
    reveal
  else
    s" undefined word " type type space
    2drop
  then
  ;

: $create
  header 6 ,
  ['] noop ,
  reveal
  ;

: create
  parse-word $create
  ;

: (does>)
  r> cell+              \ get address of code to execute
  latest @              \ backlink of just "create"d word
  cell+ cell+ !         \ write code to execute after the
                        \ new word's CFA
  ;

: does>
  ['] (does>) ,         \ compile does handling
  1 ,                   \ compile docol
  ; immediate

0 constant struct

: field
  create
    over ,
    +
  does>
    @ +
  ;

: 2constant
  create , ,
  does> 2@ reveal
  ;

\ 
\ initializer for the temporary compile buffer
\ 

: init-tmp-comp
  here 200 allot tmp-comp-buf !
;

\ the end
