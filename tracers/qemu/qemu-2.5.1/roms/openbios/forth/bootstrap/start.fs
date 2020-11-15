\ tag: forth bootstrap starter.
\ 
\ Copyright (C) 2003 Patrick Mauritz, Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

include bootstrap.fs        \ all base words
include interpreter.fs      \ interpreter
include builtin.fs          \ builtin terminal.

: include ( >filename<eol> -- )
  linefeed parse $include
;

: encode-file ( >filename< > -- dictptr size )
  parse-word $encode-file
;

: bye 
  s" Farewell!" cr type cr cr 
  0 rdepth! 
  ;

\ quit starts the outer interpreter of the forth system.
\ zech describes quit as being the outer interpreter, but
\ we split it apart to keep the interpreter elsewhere.

: quit                      ( -- )
  2 rdepth!
  outer-interpreter
;

\ initialize is the first forth word run by the kernel.
\ this word is automatically executed by the C core on start 
\ and it's never left unless something goes really wrong or
\ the user decides to leave the engine.

variable init-chain

\ :noname <definition> ; initializer
: initializer ( xt -- )
  here swap , 0 ,            \ xt, next
  init-chain
  begin dup @ while @ na1+ repeat
  !
;

: initialize-forth          ( startmem endmem -- )
  over - init-mem
  init-pockets
  init-tmp-comp
  init-builtin-terminal

  init-chain @              \ execute initializers
  begin dup while
    dup @ execute
    na1+ @
  repeat
  drop
;

\ compiler entrypoint
: initialize                ( startmem endmem -- )
  initialize-forth
  s" OpenBIOS kernel started." type cr
  quit
;
