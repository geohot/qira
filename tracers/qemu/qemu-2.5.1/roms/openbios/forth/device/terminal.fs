\ tag: terminal emulation
\ 
\ this code implements IEEE 1275-1994 ANNEX B
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

0 value (escseq)
10 buffer: (sequence)

: (match-number) ( x y [1|2] [1|2] -- x [z] )
  2dup = if \ 1 1 | 2 2
    drop exit
  then
  2dup > if
    2drop drop 1 exit
  then
  2drop 0
  ;

: (esc-number) ( maxchar -- ?? ?? num )
  >r depth >r  ( R: depth maxchar )
  0 (sequence) 2+ (escseq) 2- ( 0 seq+2 seqlen-2 )
  \ if numerical, scan until non-numerical
  0 ?do
    ( 0 seq+2 )
    dup i + c@ a
    digit if
      ( 0 ptr  n )
      rot a * + ( ptr val )
      swap 
    else
      ( 0 ptr asc )
      ascii ; = if
        0 swap
      else
        drop leave
      then
    then
    
  loop
  depth r> - r>
  0 to (escseq)
  (match-number) 
  ;
  
: (match-seq)
  (escseq) 1- (sequence) + c@  \ get last character in sequence
  \ dup draw-character
  case
    ascii A of \ CUU - cursor up
      1 (esc-number) 
      0> if 
        1 max
      else 
        1
      then
      negate line# + 
      0 max to line#
    endof
    ascii B of \ CUD - cursor down
      1 (esc-number) 
      0> if 
        1 max
	line# + 
        #lines 1- min to line#
      then
    endof
    ascii C of \ CUF - cursor forward
      1 (esc-number) 
      0> if 
        1 max
	column# + 
        #columns 1- min to column#
      then
    endof
    ascii D of \ CUB - cursor backward
      1 (esc-number) 
      0> if 
        1 max
	negate column# + 
	0 max to column#
      then
    endof
    ascii E of \ Cursor next line (CNL) 
      \ FIXME - check agains ANSI3.64
      1 (esc-number) 
      0> if 
        1 max
	line# + 
        #lines 1- min to line#
      then
      0 to column#
    endof
    ascii f of
      2 (esc-number) 
      case
        2 of
          1- #columns 1- min to column#
          1- #lines 1- min to line#
        endof
        1 of
          0 to column#
          1- #lines 1- min to line#
        endof
        0 of
          0 to column#
          0 to line#
          drop
        endof
      endcase
    endof
    ascii H of
      2 (esc-number)
      case
        2 of
          1- #columns 1- min to column#
          1- #lines 1- min to line#
        endof
        1 of
          0 to column#
          1- #lines 1- min to line#
        endof
        0 of
          0 to column#
          0 to line#
          drop
        endof
      endcase
    endof
    ascii J of
      0 to (escseq)
      #columns column# - delete-characters
      #lines line# - delete-lines
    endof
    ascii K of
      0 to (escseq)
      #columns column# - delete-characters
    endof
    ascii L of
      1 (esc-number) 
      0> if
        1 max
        insert-lines
      then
    endof
    ascii M of
      1 (esc-number) 
      1 = if
        1 max
        delete-lines
      then
    endof
    ascii @ of
      1 (esc-number) 
      1 = if
        1 max
        insert-characters 
      then
    endof
    ascii P of
      1 (esc-number) 
      1 = if
	1 max
        delete-characters
      then
    endof
    ascii m of
      1 (esc-number)
      1 = if
        7 = if 
          true to inverse?
        else
          false to inverse?
        then
      then
    endof
    ascii p of \ normal text colors
      0 to (escseq)
      inverse-screen? if
        false to inverse-screen?
	inverse? 0= to inverse?
	invert-screen
      then
    endof
    ascii q of \ inverse text colors
      0 to (escseq)
      inverse-screen? not if
        true to inverse-screen?
	inverse? 0= to inverse?
	invert-screen
      then
    endof
    ascii s of
      \ Resets the display device associated with the terminal emulator.
      0 to (escseq)
      reset-screen
    endof
  endcase
  ;

: (term-emit) ( char -- )
  toggle-cursor
  
  (escseq) 0> if
    (escseq) 10 = if
      0 to (escseq)
      ." overflow in esc" cr
      drop
    then
    (escseq) 1 = if 
      dup ascii [ = if    \ not a [
        (sequence) 1+ c!
	2 to (escseq)
      else
        0 to (escseq)      \ break out of ESC sequence
	." out of ESC" cr
	drop               \ don't print breakout character
      then
      toggle-cursor exit
    else
      (sequence) (escseq) + c! 
      (escseq) 1+ to (escseq)
      (match-seq)
      toggle-cursor exit
    then  
  then
  
  case
  0 of \ NULL
    toggle-cursor exit
  endof
  7 of \ BEL
    blink-screen
    s" /screen" s" ring-bell" 
    execute-device-method
  endof
  8 of \ BS
    column# 0<> if
      column# 1- to column#
      toggle-cursor exit
    then
  endof
  9 of \ TAB
    column# dup #columns = if 
      drop
    else
      8 + -8 and ff and to column#
    then
    toggle-cursor exit
  endof
  a of \ LF
    line# 1+ to line#
    0 to column#
    line# #lines >= if
      0 to line#
      1 delete-lines
      #lines 1- to line#
      toggle-cursor exit
    then
  endof
  b of \ VT
    line# 0<> if
      line# 1- to line#
    then
    toggle-cursor exit
  endof
  c of \ FF
    0 to column# 0 to line#
    erase-screen
  endof
  d of \ CR
    0 to column#
    toggle-cursor exit
  endof
  1b of \ ESC
    1b (sequence) c!
    1 to (escseq)
  endof

  \ draw character and advance position
  column# #columns >= if
    0 to column#
    line# 1+ to line#
    line# #lines >= if
      0 to line#
      1 delete-lines
      #lines 1- to line#
    then
  then

  dup draw-character
  column# 1+ to column#

  endcase
  toggle-cursor
  ;

['] (term-emit) to fb-emit
