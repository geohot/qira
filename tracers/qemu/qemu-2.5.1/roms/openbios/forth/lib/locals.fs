\ tag: local variables
\ 
\ Copyright (C) 2012 Mark Cave-Ayland
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\

[IFDEF] CONFIG_LOCALS

\ Init local variable stack
variable locals-var-stack
here 200 cells allot locals-var-stack !

\ Set initial stack pointer
\
\ Stack looks like this:
\ ... (sp n-2) local1 ... localm-1 localm (sp n-1)  <-- sp

locals-var-stack @ value locals-var-sp
locals-var-sp locals-var-stack @ !

0 value locals-var-count
0 value locals-flags

here 200 cells allot locals-dict-buf !

8 constant #locals

: (local1) locals-var-sp @ /n + ;
: (local2) locals-var-sp @ 2 cells + ;
: (local3) locals-var-sp @ 3 cells + ;
: (local4) locals-var-sp @ 4 cells + ;
: (local5) locals-var-sp @ 5 cells + ;
: (local6) locals-var-sp @ 6 cells + ;
: (local7) locals-var-sp @ 7 cells + ;
: (local8) locals-var-sp @ 8 cells + ;

: local1@ (local1) @ ;
: local2@ (local2) @ ;
: local3@ (local3) @ ;
: local4@ (local4) @ ;
: local5@ (local5) @ ;
: local6@ (local6) @ ;
: local7@ (local7) @ ;
: local8@ (local8) @ ;

: local1! (local1) ! ;
: local2! (local2) ! ;
: local3! (local3) ! ;
: local4! (local4) ! ;
: local5! (local5) ! ;
: local6! (local6) ! ;
: local7! (local7) ! ;
: local8! (local8) ! ;

create locals-read-table
['] local1@ ,
['] local2@ ,
['] local3@ ,
['] local4@ ,
['] local5@ ,
['] local6@ ,
['] local7@ ,
['] local8@ ,

create locals-write-table
['] local1! ,
['] local2! ,
['] local3! ,
['] local4! ,
['] local5! ,
['] local6! ,
['] local7! ,
['] local8! ,


: locals-push ( n -- )
  locals-var-sp /n + to locals-var-sp
  locals-var-sp !
;

: locals-0-push ( -- )
  0 locals-push
;
  
: (apply-local-flags) ( lfa -- )
  1 - dup c@ locals-flags or swap c!
;  

: locals-no-pop? ( lfa -- ? )
  1 - c@ 8 and 0<>
;

: locals-drop      \ Destroy current stack frame
  locals-var-sp @ to locals-var-sp
;

['] locals-drop to locals-end

: (local-init) ( str len -- )
  header 1 , 		 \ DOCOL
  ['] (lit) , ['] noop , \ read-xt
  ['] (lit) , ['] noop , \ write-xt
  ['] 2drop ,		 \ do nothing
  ['] (lit) ,
  here 5 cells - ,
  ['] @ , ['] , ,   \ store read-xt
  ['] (semis) ,
  reveal
  immediate
  last @ (apply-local-flags)
;

: (local-noop) ( str len -- )
  2drop
;

\ Word called when consuming a local variable
defer (local)

: } ( C: current latest here -- )
  here! latest ! current !           \ Switch back to normal dict
  locals-dict-buf @ to locals-dict   \ Make locals-dict visible to $find
  0 to locals-var-count
  ['] locals-var-sp ,    \ save previous sp on rstack
  ['] >r ,
  locals-dict @    \ ( last -- )
  begin
    ?dup 0<>
  while
    >r
    locals-var-count /n *
    locals-read-table + @ r@ 3 cells + !    \ set read-xt
    locals-var-count /n *
    locals-write-table + @ r@ 5 cells + !   \ set write-xt
    locals-var-count 1+ to locals-var-count
    r@ locals-no-pop? if
      ['] locals-0-push ,    \ initialise with 0
    else
      ['] locals-push ,      \ initialise from stack
    then
    r> @  \ next lfa
  repeat
  ['] r> ,
  ['] locals-push ,   \ write previous sp
; immediate

: { ( C: -- current latest here )
  current @ latest @ here
  ['] (local-init) to (local)
  0 to locals-flags
  0 to locals-var-count
  locals-dict-buf @ 200 cells 0 fill    \ Zero out temporary dictionary
  locals-dict-buf @ current !     \ Switch to locals dictionary
  locals-dict-buf @ /n + here!
  
  begin
    parse-word
    2dup s" }" strcmp 0= if
      2drop
      ['] } execute -1
    else
      2dup s" ;" strcmp 0= if
        2drop
        8 to locals-flags 0  \ Don't init from stack
      else     
        2dup s" |" strcmp 0= if
          2drop
          8 to locals-flags 0   \ Don't init from stack
        else    
          2dup s" --" strcmp 0= if
            2drop
            ['] (local-noop) to (local) 0
          else
            locals-var-count #locals < if
              (local) 0    \ accept local
            else
              s" maximum locals used ignoring " type type cr 0
            then
	    locals-var-count 1+ to locals-var-count
          then
        then
      then
    then
  until
; immediate

: -> ( n -- )
  parse-word $find if
    4 cells + @ ,
  else
    s" unable to find word " type type
  then
; immediate

[THEN]
