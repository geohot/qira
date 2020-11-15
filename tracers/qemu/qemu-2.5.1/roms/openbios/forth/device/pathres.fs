\ tag: Path resolution
\ 
\ this code implements IEEE 1275-1994 path resolution
\ 
\ Copyright (C) 2003 Samuel Rydh
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

0 value interpose-ph
0 0 create interpose-args , ,

: expand-alias ( alias-addr alias-len -- exp-addr exp-len expanded? )
  2dup
  " /aliases" find-dev 0= if 2drop false exit then
  get-package-property if
    false
  else
    2swap 2drop 
    \ drop trailing 0 from string
    dup if 1- then
    true
  then
;

\ 
\ 4.3.1 Resolve aliases
\ 

\ the returned string is allocated with alloc-mem
: pathres-resolve-aliases ( path-addr path-len -- path-addr path-len )
  over c@ 2f <> if
    200 here + >r                \ abuse dictionary for temporary storage

    \ If the pathname does not begin with "/", and its first node name 
    \ component is an alias, replace the alias with its expansion.
    ascii / split-before         \ (PATH_NAME, "/")  -> (TAIL HEAD)
    ascii : split-before         \ (HEAD, ":")  ->  (ALIAS_ARGS AL_NAME)
    expand-alias                 ( TAIL ALIAS_ARGS EXP_ALIAS_NAME expanded? )
    if
      2 pick 0<> if              \ If ALIAS_ARGS is not empty
        ascii / split-after      \ (ALIAS_NAME, "/") -> (AL_TAIL AL_HEAD/)
        2swap                    ( TAIL AL_HEAD/ AL_TAIL )
        ascii : split-before     \ (AL_TAIL, ":") -> (DEAD_ARGS AL_TAIL)
        2swap 2drop              ( TAIL AL_ARGS AL_HEAD ALIAS_TAIL )
        2swap                    ( TAIL AL_ARGS AL_TAIL AL_HEAD )
        r> tmpstrcat tmpstrcat >r
      else
        2swap 2drop              \ drop ALIAS_ARGS
      then
      r> tmpstrcat drop
    else
      \ put thing back together again
      r> tmpstrcat tmpstrcat drop
    then
  then  

  strdup
  ( path-addr path-len )
;

\ 
\ search struct
\ 

struct ( search information )
  2 cells field >si.path
  2 cells field >si.arguments
  2 cells field >si.unit_addr
  2 cells field >si.node_name
  2 cells field >si.free_me
  4 cells field >si.unit_phys
  /n field >si.unit_phys_len
  /n field >si.save-ihandle
  /n field >si.save-phandle
  /n field >si.top-ihandle
  /n field >si.top-opened        \ set after successful open
  /n field >si.child            \ node to match
constant sinfo.size


\ 
\ 4.3.6 node name match criteria
\ 

: match-nodename ( childname len sinfo -- match? )
  >r
  2dup r@ >si.node_name 2@
  ( [childname] [childname] [nodename] )
  strcmp 0= if r> 3drop true exit then

  \ does NODE_NAME contain a comma?
  r@ >si.node_name 2@ ascii , strchr
  if r> 3drop false exit then

  ( [childname] )
  ascii , left-split 2drop r@ >si.node_name 2@
  r> drop
  strcmp if false else true then
;


\ 
\ 4.3.4 exact match child node
\ 

\ If NODE_NAME is not empty, make sure it matches the name property
: common-match ( sinfo -- )
  >r
  \ a) NODE_NAME nonempty
  r@ >si.node_name 2@ nip if
    " name" r@ >si.child @ get-package-property if -1 throw then
    \ name is supposed to be null-terminated
    dup 0> if 1- then
    \ exit if NODE_NAME does not match
    r@ match-nodename 0= if -2 throw then
  then
  r> drop
;
  
: (exact-match) ( sinfo -- )
  >r
  \ a) If NODE_NAME is not empty, make sure it matches the name property
  r@ common-match

  \ b) UNIT_PHYS nonempty?
  r@ >si.unit_phys_len @ /l* ?dup if
    \ check if unit_phys matches
    " reg" r@ >si.child @ get-package-property if -3 throw then
    ( unitbytes propaddr proplen )
    rot r@ >si.unit_phys -rot
    ( propaddr unit_phys proplen unitbytes )
    swap over < if -4 throw then
    comp if -5 throw then
  else
    \ c) both NODE_NAME and UNIT_PHYS empty?
    r@ >si.node_name 2@ nip 0= if -6 throw then
  then

  r> drop
;

: exact-match ( sinfo -- match? )
  ['] (exact-match) catch if drop false exit then
  true
;

\ 
\ 4.3.5 wildcard match child node
\ 

: (wildcard-match) ( sinfo -- match? )
  >r
  \ a) If NODE_NAME is not empty, make sure it matches the name property
  r@ common-match

  \ b) Fail if "reg" property exist
  " reg" r@ >si.child @ get-package-property 0= if -7 throw then

  \ c) Fail if both NODE_NAME and UNIT_ADDR are both empty
  r@ >si.unit_phys_len @
  r@ >si.node_name 2@ nip
  or 0= if -1 throw then

  \ SUCCESS
  r> drop
;

: wildcard-match ( sinfo -- match? )
  ['] (wildcard-match) catch if drop false exit then
  true
;


\ 
\ 4.3.3 match child node
\ 

\ used if package lacks a decode-unit method
: def-decode-unit ( str len -- unitaddr ... )
  parse-hex
;

: get-decode-unit-xt ( phandle -- xt )
  " decode-unit" rot find-method
  0= if ['] def-decode-unit then
;

: find-child ( sinfo -- phandle )
  >r
  \ decode unit address string
  r@ >si.unit_addr 2@ dup if
    ( str len )
    active-package get-decode-unit-xt
    depth 3 - >r execute depth r@ - r> swap
    ( ... a_lo ... a_hi olddepth n )
    4 min 0 max
    dup r@ >si.unit_phys_len !
    ( ... a_lo ... a_hi olddepth n )
    r@ >si.unit_phys >r
    begin 1- dup 0>= while
      rot r> dup la1+ >r l!-be
    repeat
    r> 2drop
    depth!
  else
    2drop
    \ clear unit_phys
    0 r@ >si.unit_phys_len !
    \ r@ >si.unit_phys 4 cells 0 fill
  then

  ( R: sinfo )
  ['] exact-match
  begin dup while
    active-package >dn.child @
    begin ?dup while
      dup r@ >si.child !
      ( xt phandle R: sinfo )
      r@ 2 pick execute if 2drop r> >si.child @ exit then
      >dn.peer @
    repeat
    ['] exact-match = if ['] wildcard-match else 0 then
  repeat

  -99 throw  
;


\ 
\ 4.3.2 Create new linked instance procedure
\ 

: link-one ( sinfo -- )
  >r
  active-package create-instance
  dup 0= if -99 throw then

  \ change instance parent
  r@ >si.top-ihandle @ over >in.my-parent !
  dup r@ >si.top-ihandle !
  to my-self

  \ b) set my-args field
  r@ >si.arguments 2@ strdup my-self >in.arguments 2!
  
  \ e) set my-unit field
  r@ >si.unit_addr 2@ nip if
    \ copy UNIT_PHYS to the my-unit field
    r@ >si.unit_phys my-self >in.my-unit 4 cells move
  else
    \ set unit-addr from reg property
    " reg" active-package get-package-property 0= if
      \ ( ihandle prop proplen )
      \ copy address to my-unit
      4 cells min my-self >in.my-unit swap move
    else
      \ clear my-unit
      my-self >in.my-unit 4 cells 0 fill
    then
  then

  \ top instance has not been opened (yet)
  false r> >si.top-opened !
;

: invoke-open ( sinfo -- )
  " open" my-self ['] $call-method
  catch if 3drop false then
  0= if -99 throw then
    
  true swap >si.top-opened !
;

\ 
\ 4.3.7 Handle interposers procedure (supplement)
\ 

: handle-interposers ( sinfo -- )
  >r
  begin
    interpose-ph ?dup 
  while
    0 to interpose-ph
    active-package swap active-package!

    \ clear unit address and set arguments
    0 0 r@ >si.unit_addr 2!
    interpose-args 2@ r@ >si.arguments 2!
    r@ link-one
    true my-self >in.interposed !
    interpose-args 2@ free-mem
    r@ invoke-open

    active-package!
  repeat

  r> drop
;

\ 
\ 4.3.1 Path resolution procedure
\ 

\ close-dev ( ihandle -- )
\ 
: close-dev 
  begin
    dup 
  while
    dup >in.my-parent @
    swap close-package
  repeat
  drop
;

: path-res-cleanup ( sinfo close? )

  \ tear down all instances if close? is set
  if
    dup >si.top-opened @ if
      dup >si.top-ihandle @
      ?dup if close-dev then
    else
      dup >si.top-ihandle @ dup
      ( sinfo ihandle ihandle )
      dup if >in.my-parent @ swap then
      ( sinfo parent ihandle )
      ?dup if destroy-instance then
      ?dup if close-dev then
    then
  then

  \ restore active-package and my-self
  dup >si.save-ihandle @ to my-self
  dup >si.save-phandle @ active-package!

  \ free any allocated memory
  dup >si.free_me 2@ free-mem
  sinfo.size free-mem
;

: (path-resolution) ( context sinfo -- )
  >r r@ >si.path 2@
  ( context pathstr pathlen )

  \ this allocates a copy of the string
  pathres-resolve-aliases
  2dup r@ >si.free_me 2!

  \ If the pathname, after possible alias expansion, begins with "/",
  \ begin the search at the root node. Otherwise, begin at the active
  \ package.

  dup if                    \ make sure string is not empty
    over c@ 2f = if
      swap char+ swap /c -  \ Remove the "/" from PATH_NAME.
      \ Set the active package to the root node.
      device-tree @ active-package!
    then
  then

  r@ >si.path 2!
  0 0 r@ >si.unit_addr 2!
  0 0 r@ >si.arguments 2!
  0 r@ >si.top-ihandle !

  \ If there is no active package, exit this procedure, returning false.
  ( context )
  active-package 0= if -99 throw then

  \ Begin the creation of an instance chain.
  \ NOTE--If, at this step, the active package is not the root node and 
  \ we are in open-dev or execute-device-method contexts, the instance 
  \ chain that results from the path resolution process may be incomplete.

  active-package swap
  ( virt-active-node context )
  begin
    r@ >si.path 2@ nip          \ nonzero path?
  while
    \ ( active-node context )
    \ is this open-dev or execute-device-method context?
    dup if
      r@ link-one
      over active-package <> my-self >in.interposed !
      r@ invoke-open
      r@ handle-interposers
    then
    over active-package!

    r@ >si.path 2@              ( PATH )
    
    ascii / left-split          ( PATH COMPONENT )
    ascii : left-split          ( PATH ARGS NODE_ADDR )
    ascii @ left-split          ( PATH ARGS UNIT_ADDR NODE_NAME )

    r@ >si.node_name 2!
    r@ >si.unit_addr 2!
    r@ >si.arguments 2!
    r@ >si.path 2!

    ( virt-active-node context )

    \ 4.3.1 i) pathname has a leading %?
    r@ >si.node_name 2@ 2dup 2dup ascii % strchr nip = if
      1- swap 1+ swap r@ >si.node_name 2!
      " /packages" find-dev drop active-package!
      r@ find-child
    else
      2drop
      nip r@ find-child swap over
      ( new-node context new-node )
    then

    \ (optional: open any nodes between parent and child )

    active-package!
  repeat

  ( virt-active-node type )
  dup if r@ link-one then
  1 = if
    dup active-package <> my-self >in.interposed !
    r@ invoke-open 
    r@ handle-interposers
  then
  active-package!

  r> drop
;

: path-resolution ( context path-addr path-len -- sinfo true | false )
  \ allocate and clear the search block
  sinfo.size alloc-mem >r      
  r@ sinfo.size 0 fill

  \ store path
  r@ >si.path 2!

  \ save ihandle and phandle
  my-self r@ >si.save-ihandle !
  active-package r@ >si.save-phandle !
  
  \ save context (if we take an exception)
  dup

  r@ ['] (path-resolution)
  catch ?dup if
    ( context xxx xxx error )
    r> true path-res-cleanup

    \ rethrow everything except our "cleanup throw"
    dup -99 <> if throw then
    3drop

    \ ( context ) throw an exception if this is find-device context
    if false else -22 throw then
    exit
  then

  \ ( context )
  drop r> true
  ( sinfo true )
;


: open-dev ( dev-str dev-len -- ihandle | 0 )
  1 -rot path-resolution 0= if false exit then

  ( sinfo )
  my-self swap
  false path-res-cleanup

  ( ihandle )
;

: execute-device-method
( ... dev-str dev-len met-str met-len -- ... false | ?? true )
  2swap
  2 -rot path-resolution 0= if 2drop false exit then
  ( method-str method-len sinfo )
  >r
  my-self ['] $call-method catch
  if 3drop false else true then
  r> true path-res-cleanup
;

: find-device ( dev-str dev-len -- )
  2dup " .." strcmp 0= if
    2drop
    active-package dup if >dn.parent @ then
    \ ".." in root note?
    dup 0= if -22 throw then
    active-package!
    exit
  then
  0 -rot path-resolution 0= if false exit then
  ( sinfo )
  active-package swap
  true path-res-cleanup
  active-package!
;

\ find-device, but without side effects
: (find-dev) ( dev-str dev-len -- phandle true | false )
  active-package -rot
  ['] find-device catch if 3drop false exit then
  active-package swap active-package! true
;

\ Tuck on a node at the end of the chain being created.
\ This implementation follows the interpose recommended practice
\ (v0.2 draft).

: interpose ( arg-str arg-len phandle -- )
  to interpose-ph
  strdup interpose-args 2!
;

['] (find-dev) to find-dev
