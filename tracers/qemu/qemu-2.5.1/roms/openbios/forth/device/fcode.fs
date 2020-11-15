\ tag: FCode implementation functions
\ 
\ this code implements IEEE 1275-1994 ch. 5.3.3
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

hex 

0    value fcode-sys-table \ table with built-in fcodes (0-0x7ff)

true value ?fcode-offset16 \ fcode offsets are 16 instead of 8 bit?
1    value fcode-spread    \ fcode spread (1, 2 or 4)
0    value fcode-table     \ pointer to fcode table
false value ?fcode-verbose  \ do verbose fcode execution?

defer _fcode-debug?        \ If true, save names for FCodes with headers
true value fcode-headers?  \ If true, possibly save names for FCodes.

0 value fcode-stream-start \ start address of fcode stream
0 value fcode-stream       \ current fcode stream address

variable fcode-end         \ state variable, if true, fcode program terminates.
defer fcode-c@             \ get byte

: fcode-push-state ( -- <state information> )
  ?fcode-offset16
  fcode-spread
  fcode-table
  fcode-headers?
  fcode-stream-start
  fcode-stream
  fcode-end @
  ['] fcode-c@ behavior
;

: fcode-pop-state ( <state information> -- )
  to fcode-c@
  fcode-end !
  to fcode-stream
  to fcode-stream-start
  to fcode-headers?
  to fcode-table
  to fcode-spread
  to ?fcode-offset16
;
  
\ 
\ fcode access helper functions
\ 

\ fcode-ptr
\   convert FCode number to pointer to xt in FCode table.

: fcode-ptr ( u16 -- *xt )
  cells
  fcode-table ?dup if + exit then
  
  \ we are not parsing fcode at the moment
  dup 800 cells u>= abort" User FCODE# referenced."
  fcode-sys-table +
;
  
\ fcode>xt
\   get xt according to an FCode#

: fcode>xt ( u16 -- xt )
  fcode-ptr @
  ;

\ fcode-num8
\   get 8bit from FCode stream, taking spread into regard.

: fcode-num8 ( -- c ) ( F: c -- )
  fcode-stream
  dup fcode-spread + to fcode-stream 
  fcode-c@
  ;

\ fcode-num8-signed ( -- c ) ( F: c -- )
\   get 8bit signed from FCode stream

: fcode-num8-signed
  fcode-num8
  dup 80 and 0> if
     ff invert or
  then
  ;

\ fcode-num16
\   get 16bit from FCode stream

: fcode-num16 ( -- num16 )
  fcode-num8 fcode-num8 swap bwjoin
  ;

\ fcode-num16-signed ( -- c ) ( F: c -- )
\   get 16bit signed from FCode stream

: fcode-num16-signed
  fcode-num16
  dup 8000 and 0> if
     ffff invert or
  then
  ;

\ fcode-num32
\   get 32bit from FCode stream

: fcode-num32 ( -- num32 )
  fcode-num8 fcode-num8
  fcode-num8 fcode-num8
  swap 2swap swap bljoin
  ;
 
\ fcode#
\   Get an FCode# from FCode stream

: fcode# ( -- fcode# )
  fcode-num8
  dup 1 f between if
    fcode-num8 swap bwjoin
  then
  ;

\ fcode-offset
\   get offset from FCode stream.

: fcode-offset ( -- offset )
  ?fcode-offset16 if
    fcode-num16-signed
  else
    fcode-num8-signed
  then

  \ Display offset in verbose mode
  ?fcode-verbose if
    dup ."        (offset) " . cr
  then
  ;

\ fcode-string
\   get a string from FCode stream, store in pocket.

: fcode-string ( -- addr len )
  pocket dup
  fcode-num8
  dup rot c!
  2dup bounds ?do
    fcode-num8 i c!
  loop

  \ Display string in verbose mode
  ?fcode-verbose if
    2dup ."        (const) " type cr
  then
  ;
    
\ fcode-header
\   retrieve FCode header from FCode stream

: fcode-header
  fcode-num8
  fcode-num16
  fcode-num32
  ?fcode-verbose if
    ." Found FCode header:" cr rot
    ."   Format   : " u. cr swap
    ."   Checksum : " u. cr
    ."   Length   : " u. cr
  else
    3drop
  then
  \ TODO checksum
  ;

\ writes currently created word as fcode# read from stream
\ 

: fcode! ( F:FCode# -- )
  here fcode#

  \ Display fcode# in verbose mode
  ?fcode-verbose if
    dup ."        (fcode#) " . cr
  then
  fcode-ptr !
  ;

  
\ 
\ 5.3.3.1 Defining new FCode functions.
\ 

\ instance ( -- )   
\   Mark next defining word as instance specific.
\  (defined in bootstrap.fs)

\ instance-init ( wid buffer -- )
\   Copy template from specified wordlist to instance
\ 

: instance-init
  swap
  begin @ dup 0<> while
    dup /n + @ instance-cfa? if         \ buffer dict
      2dup 2 /n* + @ +                  \ buffer dict dest
      over 3 /n* + @                    \ buffer dict dest size
      2 pick 4 /n* +                    \ buffer dict dest size src
      -rot
      move
    then
  repeat
  2drop
  ;


\ new-token ( F:/FCode#/ -- ) 
\   Create a new unnamed FCode function

: new-token 
  0 0 header
  fcode!
  ;

  
\ named-token (F:FCode-string FCode#/ -- )
\   Create a new possibly named FCode function.

: named-token 
  fcode-string
  _fcode-debug? not if
    2drop 0 0
  then
  header
  fcode!
  ;

  
\ external-token (F:/FCode-string FCode#/ -- )
\   Create a new named FCode function

: external-token 
  fcode-string header
  fcode!
  ;

  
\ b(;) ( -- ) 
\   End an FCode colon definition.

: b(;)
  ['] ; execute
  ; immediate


\ b(:) ( -- ) ( E: ... -- ??? )
\   Defines type of new FCode function as colon definition.

: b(:)
  1 , ]
  ;


\ b(buffer:) ( size -- ) ( E:  -- a-addr )  
\   Defines type of new FCode function as buffer:.

: b(buffer:)
  4 , allot
  reveal
  ;

\ b(constant) ( nl -- ) ( E: -- nl )
\   Defines type of new FCode function as constant.

: b(constant)
  3 , , 
  reveal
  ;


\ b(create) ( -- ) ( E: -- a-addr )
\   Defines type of new FCode function as create word.

: b(create)
  6 , 
  ['] noop ,
  reveal
  ;


\ b(defer) ( -- ) ( E: ... -- ??? )  
\   Defines type of new FCode function as defer word.

: b(defer)
  5 ,
  ['] (undefined-defer) ,
  ['] (semis) ,
  reveal
  ;


\ b(field) ( offset size -- offset+size ) ( E: addr -- addr+offset )
\   Defines type of new FCode function as field.

: b(field)
  6 ,
  ['] noop ,
  reveal
    over ,
    +
  does>
    @ +
  ;

  
\ b(value) ( x -- ) (E: -- x )
\   Defines type of new FCode function as value.
  
: b(value)
  3 , , reveal
  ;


\ b(variable) ( -- ) ( E: -- a-addr )
\   Defines type of new FCode function as variable.

: b(variable)
  4 , 0 ,
  reveal
  ;
  
  
\ (is-user-word) ( name-str name-len xt -- ) ( E: ... -- ??? )
\   Create a new named user interface command.

: (is-user-word)
  ;

  
\ get-token ( fcode# -- xt immediate? )
\   Convert FCode number to function execution token.

: get-token
  fcode>xt dup immediate?
  ;


\ set-token ( xt immediate? fcode# -- )
\   Assign FCode number to existing function.
  
: set-token
  nip \ TODO we use the xt's immediate state for now.
  fcode-ptr !
  ;

  
  

\ 
\ 5.3.3.2 Literals
\ 


\ b(lit) ( -- n1 ) 
\   Numeric literal FCode. Followed by FCode-num32.

64bit? [IF]
: b(lit)
  fcode-num32 32>64
  state @ if
    ['] (lit) , ,
  then
  ; immediate
[ELSE]
: b(lit)
  fcode-num32 
  state @ if
    ['] (lit) , ,
  then
  ; immediate
[THEN]


\ b(') ( -- xt )  
\   Function literal FCode. Followed by FCode#

: b(')
  fcode# fcode>xt
  state @ if
    ['] (lit) , , 
  then
  ; immediate

  
\ b(") ( -- str len )
\   String literal FCode. Followed by FCode-string.
  
: b(")
  fcode-string
  state @ if
    \ only run handle-text in compile-mode,
    \ otherwise we would waste a pocket.
    handle-text
  then
  ; immediate


\ 
\ 5.3.3.3 Controlling values and defers
\ 

\ behavior ( defer-xt -- contents-xt )
\ defined in bootstrap.fs

\ b(to) ( new-value -- )
\   FCode for setting values and defers. Followed by FCode#.

: b(to)
  fcode# fcode>xt 
  1 handle-lit
  ['] (to)
  state @ if 
    ,
  else
    execute
  then
  ; immediate



\ 
\ 5.3.3.4 Control flow
\ 


\ offset16 ( -- )
\   Makes subsequent FCode-offsets use 16-bit (not 8-bit) form.

: offset16
  true to ?fcode-offset16
  ;


\ bbranch ( -- )
\   Unconditional branch FCode. Followed by FCode-offset.
  
: bbranch
  fcode-offset 0< if \ if we jump backwards, we can forsee where it goes
    ['] dobranch ,
    resolve-dest
    execute-tmp-comp
  else
    setup-tmp-comp ['] dobranch ,
    here 0
    0 ,
    2swap
  then
  ; immediate


\ b?branch ( continue? -- )
\   Conditional branch FCode. Followed by FCode-offset.

: b?branch
  fcode-offset 0< if \ if we jump backwards, we can forsee where it goes
    ['] do?branch ,
    resolve-dest
    execute-tmp-comp
  else
    setup-tmp-comp ['] do?branch ,
    here 0
    0 ,
  then 
  ; immediate

  
\ b(<mark) ( -- )
\   Target of backward branches.

: b(<mark)
  setup-tmp-comp
  here 1
  ; immediate

  
\ b(>resolve) ( -- )
\   Target of forward branches.

: b(>resolve)
  resolve-orig
  execute-tmp-comp
  ; immediate

  
\ b(loop) ( -- )
\   End FCode do..loop. Followed by FCode-offset.

: b(loop)
  fcode-offset drop
  postpone loop
  ; immediate

  
\ b(+loop) ( delta -- )
\   End FCode do..+loop. Followed by FCode-offset.

: b(+loop)
  fcode-offset drop
  postpone +loop
  ; immediate

  
\ b(do) ( limit start -- )
\   Begin FCode do..loop. Followed by FCode-offset.

: b(do)
  fcode-offset drop
  postpone do
  ; immediate

  
\ b(?do) ( limit start -- )
\   Begin FCode ?do..loop. Followed by FCode-offset.

: b(?do)
  fcode-offset drop
  postpone ?do
  ; immediate

  
\ b(leave) ( -- )
\   Exit from a do..loop.
  
: b(leave)
  postpone leave
  ; immediate

  
\ b(case) ( sel -- sel )
\   Begin a case (multiple selection) statement.

: b(case)
  postpone case
  ; immediate

  
\ b(endcase) ( sel | <nothing> -- )
\   End a case (multiple selection) statement.

: b(endcase)
  postpone endcase
  ; immediate
  

\ b(of) ( sel of-val -- sel | <nothing> )
\   FCode for of in case statement. Followed by FCode-offset.

: b(of)
  fcode-offset drop
  postpone of
  ; immediate

\ b(endof) ( -- )
\   FCode for endof in case statement. Followed by FCode-offset.

: b(endof)
  fcode-offset drop
  postpone endof
  ; immediate
