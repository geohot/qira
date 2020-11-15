\ tag: Forth Decompiler 
\ 
\ this code implements IEEE 1275-1994 ch. 7.5.3.2
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

1 value (see-indent) 

: (see-cr)
  cr (see-indent) spaces
  ;

: indent+
  (see-indent) 2+ to (see-indent)
  ;

: indent-
  (see-indent) 2- to (see-indent)
  ;
  
: (see-colon)
  dup ." : " cell - lfa2name type (see-cr)
   begin
   cell+ dup @ dup ['] (semis) <>
   while
    space
    dup
    case

      ['] do?branch of
        ." if" (see-cr) indent+
        drop cell+ 
      endof
      
      ['] dobranch of
      	." then" indent- (see-cr)
	drop cell+ 
      endof
      
      ['] (begin) of
        ." begin" indent+ (see-cr) 
	drop
      endof

      ['] (again) of
      	." again" (see-cr) 
	drop
      endof

      ['] (until) of
        ." until" (see-cr)
	drop
      endof

      ['] (while) of
        indent- (see-cr)
      	."  while" 
	indent+ (see-cr)
	drop 2 cells +
      endof

      ['] (repeat) of
        indent- (see-cr) 
        ."  repeat" 
	(see-cr) 
        drop 2 cells +
      endof

      ['] (lit) of
        ." ( lit ) h# " 
	drop 1 cells +
	dup @ u.
      endof

      ['] (") of
        22 emit space drop dup cell+ @ 
	2dup swap 2 cells + swap type 
	22 emit
	+ aligned cell+
      endof

      cell - lfa2name type 
    endcase
   repeat
  cr ."   ;"
  2drop
  ;

: (see) ( xt -- )
  cr
  dup @ case
    1 of 
      (see-colon)  
    endof
    3 of 
      ." constant " dup cell - lfa2name type ."  =  " execute . 
    endof
    4 of 
      ." variable " dup cell - lfa2name type ."  =  " execute @ . 
    endof
    5 of 
      ." defer " dup  cell - lfa2name type cr 
      ." is " cell+ @ cell - lfa2name type cr
    endof
    ." primword " swap cell - lfa2name type 
  endcase
  cr
  ;

: see ' (see) ;
