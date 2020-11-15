\ tag: Display device management
\ 
\ this code implements IEEE 1275-1994 ch. 5.3.6
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

hex 

\ 
\ 5.3.6.1 Terminal emulator routines
\ 

\ The following values are used and set by the terminal emulator
\ defined and described in 3.8.4.2
0 value line# ( -- line# )
0 value column# ( -- column# )
0 value inverse? ( -- white-on-black? )
0 value inverse-screen? ( -- black? )
0 value #lines ( -- rows )
0 value #columns ( -- columns )

\ The following values are used internally by both the 1-bit and the 
\ 8-bit frame-buffer support routines.
  
0 value frame-buffer-adr ( -- addr )
0 value screen-height    ( -- height )
0 value screen-width     ( -- width )
0 value window-top       ( -- border-height )
0 value window-left      ( -- border-width )
0 value char-height      ( -- height )
0 value char-width       ( -- width )
0 value fontbytes        ( -- bytes )

\ these values are used internally and do not represent any
\ official open firmware words
0 value char-min
0 value char-num
0 value font

0 value foreground-color
0 value background-color
create color-palette 100 cells allot

2 value font-spacing
0 value depth-bits
0 value line-bytes
0 value display-ih

\ internal values
0 value openbios-video-height
0 value openbios-video-width

\ The following wordset is called the "defer word interface" of the 
\ terminal-emulator support package. It gets overloaded by fb1-install
\ or fb8-install (initiated by the framebuffer fcode driver)

defer draw-character    ( char -- )
defer reset-screen      ( -- )
defer toggle-cursor     ( -- )
defer erase-screen      ( -- )
defer blink-screen      ( -- )
defer invert-screen     ( -- )
defer insert-characters ( n -- )
defer delete-characters ( n -- )
defer insert-lines ( n -- )
defer delete-lines ( n -- )
defer draw-logo ( line# addr width height -- )

defer fb-emit ( x -- )

: depth-bytes ( -- bytes )
  depth-bits 1+ 8 /
;

\ 
\ 5.3.6.2 Frame-buffer support routines
\ 

: default-font ( -- addr width height advance min-char #glyphs )
  (romfont) (romfont-width) (romfont-height) (romfont-height) 0 100
  ;

: set-font ( addr width height advance min-char #glyphs -- )
  to char-num
  to char-min
  to fontbytes
  font-spacing + to char-height
  to char-width
  to font
  ;

: >font ( char -- addr )
  char-min - 
  char-num min
  fontbytes *
  font +
  ;

\ 
\ 5.3.6.3 Display device support
\ 

\ 
\ 5.3.6.3.1 Frame-buffer package interface
\ 

: is-install    ( xt -- )
  external
  \ Create open and other methods for this display device.
  \ Methods to be created: open, write, draw-logo, restore
  s" open" header 
  1 , \ colon definition
  ,
  ['] (lit) ,
  -1 ,
  ['] (semis) ,
  reveal
  s" : write dup >r bounds do i c@ fb-emit loop r> ; " evaluate
  s" : draw-logo draw-logo ; " evaluate
  s" : restore reset-screen ; " evaluate
  ;

: is-remove    ( xt -- )
  external
  \ Create close method for this display device.
  s" close" header 
  1 , \ colon definition
  ,
  ['] (semis) ,
  reveal
  ;
  
: is-selftest    ( xt -- )
  external
  \ Create selftest method for this display device.
  s" selftest" header 
  1 , \ colon definition
  ,
  ['] (semis) ,
  reveal
  ;


\ 5.3.6.3.2 Generic one-bit frame-buffer support (optional)

: fb1-nonimplemented
  ." Monochrome framebuffer support is not implemented." cr
  end0
  ;

: fb1-draw-character	fb1-nonimplemented ; \ historical
: fb1-reset-screen	fb1-nonimplemented ;
: fb1-toggle-cursor	fb1-nonimplemented ;
: fb1-erase-screen	fb1-nonimplemented ;
: fb1-blink-screen	fb1-nonimplemented ;
: fb1-invert-screen	fb1-nonimplemented ;
: fb1-insert-characters fb1-nonimplemented ;
: fb1-delete-characters	fb1-nonimplemented ;
: fb1-insert-lines	fb1-nonimplemented ;
: fb1-delete-lines	fb1-nonimplemented ;
: fb1-slide-up		fb1-nonimplemented ;
: fb1-draw-logo		fb1-nonimplemented ;
: fb1-install		fb1-nonimplemented ;

  
\ 5.3.6.3.3 Generic eight-bit frame-buffer support

\ bind to low-level C function later
defer fb8-blitmask
defer fb8-fillrect
defer fb8-invertrect

: fb8-line2addr ( line -- addr )
  window-top +
  screen-width * depth-bytes *
  frame-buffer-adr + 
  window-left depth-bytes * +
;

: fb8-curpos2addr ( col line -- addr )
  char-height * fb8-line2addr
  swap char-width * depth-bytes * +
;

: fb8-copy-lines ( count from to -- )
  fb8-line2addr swap
  fb8-line2addr swap
  #columns char-width * depth-bytes *
  3 pick * move drop
;

: fb8-clear-lines ( count line -- )
  background-color 0
  2 pick window-top +
  #columns char-width *
  5 pick
  fb8-fillrect
  2drop
;
  
: fb8-draw-character ( char -- )
  \ erase the current character
  background-color
  column# char-width * window-left +
  line# char-height * window-top +
  char-width char-height fb8-fillrect
  \ draw the character:
  >font  
  line# char-height * window-top + screen-width * depth-bytes *
  column# char-width * depth-bytes *
  window-left depth-bytes * + + frame-buffer-adr +
  swap char-width char-height font-spacing -
  \ normal or inverse?
  foreground-color background-color
  inverse? if
    swap
  then
  fb8-blitmask
  ;

: fb8-reset-screen ( -- )
  false to inverse?
  false to inverse-screen?
  0 to foreground-color 
  d# 15 to background-color

  \ override with OpenBIOS defaults
  fe to background-color
  0 to foreground-color
  ;

: fb8-toggle-cursor ( -- )
  column# char-width * window-left +
  line# char-height * window-top +
  char-width char-height font-spacing -
  foreground-color background-color
  fb8-invertrect
  ;

: fb8-erase-screen ( -- )
  inverse-screen? if
    foreground-color
  else
    background-color
  then
  0 0 screen-width screen-height
  fb8-fillrect
  ;

: fb8-invert-screen ( -- )
  0 0 screen-width screen-height
  background-color foreground-color
  fb8-invertrect
  ;

: fb8-blink-screen ( -- )
  fb8-invert-screen 2000 ms
  fb8-invert-screen
  ;
  
: fb8-insert-characters ( n -- )
  \ numcopy = ( #columns - column# - n )
  #columns over - column# -
  char-width * depth-bytes * ( n numbytescopy )

  over column# + line# fb8-curpos2addr
  column# line# fb8-curpos2addr ( n numbytescopy destaddr srcaddr )
  char-height 0 do
    3dup swap rot move
    line-bytes + swap line-bytes + swap
  loop 3drop
  
  background-color
  column# char-width * window-left + line# char-height * window-top +
  3 pick char-width * char-height
  fb8-fillrect
  drop
  ;

: fb8-delete-characters ( n -- )
  \ numcopy = ( #columns - column# - n )
  #columns over - column# -
  char-width * depth-bytes * ( n numbytescopy )

  over column# + line# fb8-curpos2addr
  column# line# fb8-curpos2addr swap ( n numbytescopy destaddr srcaddr )
  char-height 0 do
    3dup swap rot move
    line-bytes + swap line-bytes + swap
  loop 3drop

  background-color
  over #columns swap - char-width * window-left + line# char-height * window-top +
  3 pick char-width * char-height
  fb8-fillrect
  drop
  ;

: fb8-insert-lines ( n -- )
  \ numcopy = ( #lines - n )
  #lines over - char-height *
  over line# char-height *
  swap char-height * over +
  fb8-copy-lines

  char-height * line# char-height *
  fb8-clear-lines
  ;
  
: fb8-delete-lines ( n -- )
  \ numcopy = ( #lines - ( line# + n )) * char-height
  #lines over line# + - char-height *
  over line# + char-height *
  line# char-height *
  fb8-copy-lines
  
  #lines over - char-height *
  dup #lines char-height * swap - swap
  fb8-clear-lines
  drop
;


: fb8-draw-logo ( line# addr width height -- )
  2swap swap
  char-height  * window-top  + 
  screen-width * window-left +
  frame-buffer-adr + 
  swap 2swap
  \ in-fb-start-adr logo-adr logo-width logo-height 

  fb8-blitmask ( fbaddr mask-addr width height --  )
;


: fb8-install ( width height #columns #lines -- )

  \ set state variables
  to #lines
  to #columns
  to screen-height
  to screen-width

  screen-width #columns char-width * - 2/ to window-left
  screen-height #lines char-height * - 2/ to window-top
  
  0 to column#
  0 to line#
  0 to inverse? 
  0 to inverse-screen?

  my-self to display-ih

  \ set /chosen display property
  my-self active-package 0 to my-self
  " /chosen" (find-dev) 0<> if
    active-package!
    display-ih encode-int " display" property
  then
  active-package! to my-self

  \ set defer functions to 8bit versions

  ['] fb8-draw-character to draw-character
  ['] fb8-toggle-cursor to toggle-cursor
  ['] fb8-erase-screen to erase-screen
  ['] fb8-blink-screen to blink-screen
  ['] fb8-invert-screen to invert-screen
  ['] fb8-insert-characters to insert-characters
  ['] fb8-delete-characters to delete-characters
  ['] fb8-insert-lines to insert-lines
  ['] fb8-delete-lines to delete-lines
  ['] fb8-draw-logo to draw-logo
  ['] fb8-reset-screen to reset-screen

  \ recommended practice
  s" iso6429-1983-colors" get-my-property if
    0 ff
  else
    2drop d# 15 0
  then
  to foreground-color to background-color

  \ setup palette
  10101 ['] color-palette cell+ ff 0 do
    dup 2 pick i * swap ! cell+
  loop 2drop

  \ special background color
  ffffcc ['] color-palette cell+ fe cells + !

  \ load palette onto the hardware
  ['] color-palette cell+ ff 0 do
    dup @ ff0000 and d# 16 rshift
    1 pick @ ff00 and d# 8 rshift
    2 pick @ ff and
    i
    s" color!" $find if
      execute
    else
      2drop
    then
    cell+
  loop drop

  \ ... but let's override with some better defaults
  fe to background-color
  0 to foreground-color

  fb8-erase-screen

  \ If we have a startup splash then display it
  [IFDEF] CONFIG_MOL
      mol-startup-splash 2000 ms
      fb8-erase-screen
  [THEN]
;
