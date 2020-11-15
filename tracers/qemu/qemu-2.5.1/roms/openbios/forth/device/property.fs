\ tag: Property management
\ 
\ this code implements IEEE 1275-1994 ch. 5.3.5
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

\ small helpers.. these should go elsewhere.
: bigendian?
  10 here ! here c@ 10 <>
  ;

: l!-be ( val addr )
  3 bounds swap do
    dup ff and i c! 
    8 rshift
  -1 +loop
  drop
  ;

: l@-be ( addr )
  0 swap 4 bounds do
    i c@ swap 8 << or
  loop
  ;

\ allocate n bytes for device tree information
\ until I know where to put this, I put it in the
\ dictionary.

: alloc-tree ( n -- addr )
  dup >r           \ save len
  here swap allot
  dup r> 0 fill    \ clear memory
  ;

: align-tree ( -- )
  null-align
  ;

: no-active true abort" no active package." ;

\ 
\ 5.3.5 Property management
\ 

\ Helper function
: find-property ( name len phandle -- &&prop|0 )
  >dn.properties
  begin
    dup @
  while
    dup @ >prop.name @  ( name len prop propname )
    2over comp0         ( name len prop equal? )
    0= if nip nip exit then
    >prop.next @
  repeat
  ( name len false )
  3drop false
  ;

\ From package (5.3.4.1)
: next-property 
( previous-str previous-len phandle -- false | name-str name-len true )
  >r
  2dup 0= swap 0= or if
    2drop r> >dn.properties @
  else
    r> find-property dup if @ then
    dup if >prop.next @ then
  then

  ?dup if
    >prop.name @ dup cstrlen true
    ( phandle name-str name-len true )
  else
    false
  then
;


\ 
\ 5.3.5.4 Property value access
\ 

\ Return value for name string property in package phandle.
: get-package-property
  ( name-str name-len phandle -- true | prop-addr prop-len false )
  find-property ?dup if
    @ dup >prop.addr @
    swap >prop.len  @
    false
  else
    true
  then
  ;

\ Return value for given property in the current instance or its parents.
: get-inherited-property 
  ( name-str name-len -- true | prop-addr prop-len false )
  my-self 
  begin
    ?dup
  while
    dup >in.device-node @   ( str len ihandle phandle )
    2over rot find-property ?dup if
      @
      ( str len ihandle prop )
      nip nip nip ( prop )
      dup >prop.addr @ swap >prop.len @
      false 
      exit
    then
    ( str len ihandle )
    >in.my-parent @
  repeat
  2drop
  true
  ;

\ Return value for given property in this package.
: get-my-property ( name-str name-len -- true | prop-addr prop-len false )
  my-self >in.device-node @  ( -- phandle )
  get-package-property
  ;


\   
\ 5.3.5.2 Property array decoding
\ 

: decode-int ( prop-addr1 prop-len1 -- prop-addr2 prop-len2 n )
  dup 0> if
    dup 4 min >r     ( addr1 len1 R:minlen )
    over r@ + swap   ( addr1 addr2 len1 R:minlen )
    r> -             ( addr1 addr2 len2 )
    rot l@-be
  else
    0
  then
  ;

\ HELPER: get #address-cell value (from parent)
\ Legal values are 1..4 (we may optionally support longer addresses)
: my-#acells ( -- #address-cells )
  my-self ?dup if >in.device-node @ else active-package then
  ?dup if >dn.parent @ then
  ?dup if
    " #address-cells" rot get-package-property if 2 exit then
    \ we don't have to support more than 4 (and 0 is illegal)
    decode-int nip nip 4 min 1 max
  else
    2
  then
;

\ HELPER: get #size-cells value (from parent)
: my-#scells ( -- #size-cells )
  my-self ?dup if >in.device-node @ else active-package then
  ?dup if >dn.parent @ then
  ?dup if
    " #size-cells" rot get-package-property if 1 exit then
    decode-int nip nip
  else
    1
  then
;

: decode-string ( prop-addr1 prop-len1 -- prop-addr2 prop-len2 str len )
  dup 0> if
    2dup bounds \ check property for 0 bytes
    0 -rot      \ initial string len is 0
    do
      i c@ 0= if
        leave
      then
      1+
    loop              ( prop-addr1 prop-len1 len )
    1+ rot >r         ( prop-len1 len R: prop-addr1 )
    over min 2dup -   ( prop-len1 nlen prop-len2 R: prop-addr1 )
    r@ 2 pick +       ( prop-len1 nlen prop-len2 prop-addr2 )
    >r >r >r          ( R: prop-addr1 prop-addr2 prop-len2 nlen )
    drop
    r> r> r>          ( nlen prop-len2 prop-addr2 )
    -rot swap 1-      ( prop-addr2 prop-len2 nlen )
    r> swap           ( prop-addr2 prop-len2 str len )
  else
    0 0
  then
  ;

: decode-bytes  ( addr1 len1 #bytes -- addr len2 addr1 #bytes )
  tuck -  ( addr1 #bytes len2 )
  r> 2dup +  ( addr1 #bytes addr2 ) ( R: len2 )
  r> 2swap
  ;
  
: decode-phys 
  ( prop-addr1 prop-len1 -- prop-addr2 prop-len2 phys.lo ...  phys.hi )
  my-#acells 0 ?do
    decode-int r> r> rot >r >r >r
  loop
  my-#acells 0 ?do
    r> r> r> -rot >r >r 
  loop
  ;

  
\ 
\ 5.3.5.1 Property array encoding
\ 

: encode-int    ( n -- prop-addr prop-len )
  /l alloc-tree tuck l!-be /l
  ;

: encode-string ( str len -- prop-addr prop-len )
  \ we trust len here. should probably check string?
  tuck char+ alloc-tree ( len str prop-addr )
  tuck 3 pick move      ( len prop-addr )
  swap 1+
  ;

: encode-bytes ( data-addr data-len -- prop-addr prop-len )
  tuck alloc-tree ( len str prop-addr )
  tuck 3 pick move
  swap
  ;

: encode+ ( prop-addr1 prop-len1 prop-addr2 prop-len2 -- prop-addr3 prop-len3 )
  nip +
  ;

: encode-phys ( phys.lo ... phys.hi -- prop-addr prop-len )
  encode-int my-#acells 1- 0 ?do
    rot encode-int encode+
  loop
  ;

defer sbus-intr>cpu ( sbus-intr# -- cpu-intr# )
: (sbus-intr>cpu) ." No SBUS present on this machine." cr ;
['] (sbus-intr>cpu) to sbus-intr>cpu


\ 
\ 5.3.5.3 Property declaration
\ 

: (property) ( prop-addr prop-len name-str name-len dnode -- )
  >r 2dup r@
  align-tree
  find-property ?dup if 
    \ If a property with that property name already exists in the 
    \ package in which the property would be created, replace its
    \ value with the new value.
    @ r> drop        \ don't need the device node anymore.
    -rot 2drop tuck  \ drop property name 
    >prop.len  !     \ overwrite old values
    >prop.addr !
    exit
  then

  ( prop-addr prop-len name-str name-len R: dn )
  prop-node.size alloc-tree
  dup >prop.next off
  
  dup r> >dn.properties
  begin dup @ while @ >prop.next repeat !
  >r
  
  ( prop-addr prop-len name-str name-len R: prop )
  
  \ create copy of property name
  dup char+ alloc-tree 
  dup >r swap move r>
  ( prop-addr prop-len new-name R: prop )
  r@ >prop.name !
  r@ >prop.len  !
  r> >prop.addr !
  align-tree 
  ;

: property ( prop-addr prop-len name-str name-len -- )
  my-self ?dup if
    >in.device-node @
  else
    active-package
  then
  dup if
    (property)
  else
    no-active
  then
  ;

: (delete-property) ( name len dnode -- )
  find-property ?dup if
    dup @ >prop.next @ swap !
    \ maybe we should try to reclaim the space?
  then
;
  
: delete-property ( name-str name-len -- )
  active-package ?dup if
    (delete-property)
  else
    2drop
  then
  ;

\ Create the "name"  property; value is indicated string.
: device-name    ( str len -- )
  encode-string  " name"  property
  ;

\ Create "device_type" property, value is indicated string.
: device-type    ( str len -- )
  encode-string  " device_type"  property
  ;

\ Create the "reg" property with the given values.
: reg ( phys.lo ... phys.hi size -- )
  >r  ( phys.lo ... phys.hi ) encode-phys  ( addr len )
  r>  ( addr1 len1 size )     encode-int   ( addr1 len1 addr2 len2 )
  encode+  ( addr len )
  " reg"  property
  ;

\ Create the "model" property; value is indicated string.
: model    ( str len -- )
  encode-string  " model"  property
  ;
