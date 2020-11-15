\ 7.6 Client Program Debugging command group


\ 7.6.1    Registers display

: ctrace    ( -- )
  ;
  
: .registers    ( -- )
  ;

: .fregisters    ( -- )
  ;

\ to    ( param [old-name< >] -- )


\ 7.6.2    Program download and execute

struct ( saved-program-state )
  /n field >sps.entry
  /n field >sps.file-size
  /n field >sps.file-type
constant saved-program-state.size
create saved-program-state saved-program-state.size allot

variable state-valid
0 state-valid !

variable file-size

: !load-size file-size ! ;

: load-size file-size @ ;


\ File types identified by (init-program)

0  constant elf-boot
1  constant elf
2  constant bootinfo
3  constant xcoff
4  constant pe
5  constant aout
10 constant fcode
11 constant forth
12 constant bootcode


: init-program    ( -- )
  \ Call down to the lower level for relocation etc.
  s" (init-program)" $find if
    execute
  else
    s" Unable to locate (init-program)!" type cr
  then
  ;

: (find-bootdevice) ( param-str param-len -- bootpath-str bootpath-len)
  \ Parse the <param> string which is a space-separated list of one or
  \ more potential boot devices, and return the first one that can be
  \ successfully opened.

  \ Space-separated bootpath string
  bl left-split 	\ bootpathstr bootpathstr-len bootdevstr bootdevstr-len
  dup 0= if

    \ None specified. As per IEEE-1275 specification, search through each value
    \ in boot-device and use the first that returns a valid ihandle on open.

    2drop		\ drop the empty device string as we're going to use our own

    s" boot-device" $find drop execute 
    bl left-split
    begin 
      dup 
    while
      2dup s" Trying " type type s" ..." type cr
      2dup open-dev ?dup if
        close-dev
	2swap drop 0	\ Fake end of string so we exit loop
      else
        2drop
        bl left-split
      then
    repeat
    2drop
  then

  \ bootargs
  2swap dup 0= if
    \ None specified, use default from nvram
    2drop s" boot-file" $find drop execute
  then

  \ Set the bootargs property
  encode-string
  " /chosen" (find-dev) if
    " bootargs" rot (property)
  then
;

\ Locate the boot-device opened by this ihandle (currently taken as being
\ the first non-interposed package in the instance chain)

: ihandle>boot-device-handle ( ihandle -- 0 | device-ihandle -1 )
  >r 0
  begin r> dup >in.my-parent @ dup >r while
    ( result ihandle R: ihandle.parent )
    dup >in.interposed @ 0= if
      \ Find the first non-interposed package
      over 0= if
        swap drop
      else
        drop
      then
    else
      drop
    then
  repeat
  r> drop drop

  dup 0<> if
    -1
  then
;

: $load ( devstr len )
  open-dev ( ihandle )
  dup 0= if
    drop
    exit
  then
  dup >r
  " load-base" evaluate swap ( load-base ihandle )
  dup ihandle>phandle " load" rot find-method ( xt 0|1 )
  if swap call-package !load-size else cr ." Cannot find load for this package" 2drop then

  \ If the boot device path doesn't contain an explicit partition id, e.g. cd:,\\:tbxi
  \ then the interposed partition package may have auto-probed a suitable partition. If
  \ this is the case then it will have set the " selected-partition-args" property in
  \ the partition package to contain the new device arguments.
  \
  \ In order to ensure that bootpath contains the partition argument, we use the contents
  \ of this property if it exists to override the boot device arguments when generating
  \ the full bootpath using get-instance-path.

  my-self
  r@ to my-self
  " selected-partition-args" get-inherited-property 0= if
    decode-string 2swap 2drop
    ( myself-save partargs-str partargs-len )
    r@ ihandle>boot-device-handle if
      ( myself-save partargs-str partargs-len block-ihandle )
      \ Override the arguments before get-instance-path
      dup >in.arguments 2@ >r >r dup >r    ( R: block-ihandle arg-len arg-str )
      >in.arguments 2!    ( myself-save )
      r@ " get-instance-path" $find if
        execute   ( myself-save bootpathstr bootpathlen )
      then
      \ Now write the original arguments back
      r> r> r> rot >in.arguments 2!   ( myself-save bootpathstr bootpathlen  R: )
      rot    ( bootpathstr bootpathlen myself-save )
    then
  else
    my-self " get-instance-path" $find if
      execute  ( myself-save bootpathstr pathlen )
      rot    ( bootpathstr bootpathlen myself-save )
    then
  then
  to my-self

  \ Set bootpath property in /chosen
  encode-string " /chosen" (find-dev) if
    " bootpath" rot (property)
  then

  r> close-dev
  init-program
  ;

: load    ( "{params}<cr>" -- )
  linefeed parse
  (find-bootdevice)
  $load
;

: dir ( "{paths}<cr>" -- )
  linefeed parse
  ascii , split-after
  2dup open-dev dup 0= if
    drop
    cr ." Unable to locate device " type
    2drop
    exit
  then
  -rot 2drop -rot 2 pick
  " dir" rot ['] $call-method catch
  if
    3drop
    cr ." Cannot find dir for this package"
  then
  close-dev
;

: go    ( -- )
  state-valid @ not if
    s" No valid state has been set by load or init-program" type cr
    exit 
  then

  \ Call the architecture-specific code to launch the client image
  s" (go)" $find if
    execute
  else
    ." go is not yet implemented"
    2drop
  then
  ;


\ 7.6.3    Abort and resume

\ already defined !?
\ : go    ( -- )
\   ;

  
\ 7.6.4    Disassembler

: dis    ( addr -- )
  ;
  
: +dis    ( -- )
  ;

\ 7.6.5    Breakpoints
: .bp    ( -- )
  ;

: +bp    ( addr -- )
  ;

: -bp    ( addr -- )
  ;

: --bp    ( -- )
  ;

: bpoff    ( -- )
  ;

: step    ( -- )
  ;

: steps    ( n -- )
  ;

: hop    ( -- )
  ;

: hops    ( n -- )
  ;

\ already defined
\ : go    ( -- )
\   ;

: gos    ( n -- )
  ;

: till    ( addr -- )
  ;

: return    ( -- )
  ;

: .breakpoint    ( -- )
  ;

: .step    ( -- )
  ;

: .instruction    ( -- )
  ;


\ 7.6.6    Symbolic debugging
: .adr    ( addr -- )
  ;

: sym    ( "name< >" -- n )
  ;

: sym>value    ( addr len -- addr len false | n true )
  ;

: value>sym    ( n1 -- n1 false | n2 addr len true )
  ;
