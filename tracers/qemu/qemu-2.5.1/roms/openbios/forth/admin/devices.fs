\ tag: device tree administration
\ 
\ this code implements IEEE 1275-1994 
\ 
\ Copyright (C) 2003 Samuel Rydh
\ Copyright (C) 2003-2006 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 


\ 7.4.11.1 Device alias

: devalias    ( "{alias-name}< >{device-specifier}<cr>" -- )
  ;
  
: nvalias    ( "alias-name< >device-specifier<cr>" -- )
  ;
  
: $nvalias    ( name-str name-len dev-str dev-len -- )
  ;

: nvunalias    ( "alias-name< >" -- )
  ;
  
: $nvunalias    ( name-str name-len -- )
  ;


\ 7.4.11.2 Device tree browsing

: dev    ( "<spaces>device-specifier" -- )
  bl parse
  find-device
;

: cd
  dev
;
  
\ find-device    ( dev-str dev-len -- )
\ implemented in pathres.fs

: device-end    ( -- )
  0 active-package!
  ;

\ Open selected device node and make it the current instance
\   section H.8 errata: pre OpenFirmware, but Sun OBP compatible
: select-dev    ( -- )
  open-dev dup 0= abort" failed opening parent."
  dup to my-self
  ihandle>phandle active-package!
;

\ Close current node, deselect active package and current instance,
\ leaving no instance selected
\   section H.8 errata: pre OpenFirmware, but Sun OBP compatible
: unselect-dev ( -- )
  my-self close-dev
  device-end
  0 to my-self
;

: begin-package ( arg-str arg-len reg-str reg-len dev-str dev-len -- )
  select-dev
  new-device
  set-args
;

: end-package   ( -- )
  finish-device
  unselect-dev
;
 
: ?active-package ( -- phandle )
  active-package dup 0= abort" no active device"
;

\ -------------------------------------------------------
\  path handling
\ -------------------------------------------------------

\ used if parent lacks an encode-unit method
: def-encode-unit ( unitaddr ... )
    pocket tohexstr
;

: get-encode-unit-xt ( phandle.parent -- xt )
  >dn.parent @
  " encode-unit" rot find-method
  0= if ['] def-encode-unit then
;

: get-nodename ( phandle -- str len )
  " name" rot get-package-property if " <noname>" else 1- then  
;

\ helper, return the node name in the format 'cpus@addr'
: pnodename ( phandle -- str len )
  dup get-nodename rot
  dup " reg" rot get-package-property if drop exit then rot

  \ set active-package and clear my-self (decode-phys needs this)
  my-self >r 0 to my-self
  active-package >r
  dup active-package!

  ( name len prop len phandle )
  get-encode-unit-xt

  ( name len prop len xt )
  depth >r >r
  decode-phys r> execute
  r> -rot >r >r depth! 3drop

  ( name len R: len str )
  r> r> " @"
  here 20 +              \ abuse dictionary for temporary storage
  tmpstrcat >r
  2swap r> tmpstrcat drop
  pocket tmpstrcpy drop
  
  r> active-package!
  r> to my-self
;

: inodename ( ihandle -- str len )
  my-self over to my-self >r
  ihandle>phandle get-nodename
  
  \ nonzero unit number?
  false >r
  depth >r my-unit r> 1+
  begin depth over > while
    swap 0<> if r> drop true >r then
  repeat
  drop

  \ if not... check for presence of "reg" property
  r> ?dup 0= if
    " reg" my-self ihandle>phandle get-package-property
    if false else 2drop true then
  then
  
  ( name len print-unit-flag )
  if
    my-self ihandle>phandle get-encode-unit-xt

    ( name len xt )
    depth >r >r
    my-unit r> execute
    r> -rot >r >r depth! drop
    r> r>
    ( name len str len )
    here 20 + tmpstrcpy 
    " @" rot tmpstrcat drop
    2swap pocket tmpstrcat drop
  then

  \ add :arguments
  my-args dup if
    " :" pocket tmpstrcat drop
    2swap pocket tmpstrcat drop
  else
    2drop
  then
  
  r> to my-self
;

\ helper, also used by client interface (package-to-path)
: get-package-path ( phandle -- str len )
  ?dup 0= if 0 0 then

  dup >dn.parent @ 0= if drop " /" exit then
  \ dictionary abused for temporary storage
  >r 0 0 here 40 + 
  begin r> dup >dn.parent @ dup >r while
    ( path len tempbuf phandle R: phandle.parent )
    pnodename rot tmpstrcat
    " /" rot tmpstrcat
  repeat
  r> 3drop
  pocket tmpstrcpy drop
;

\ used by client interface (instance-to-path)
: get-instance-path ( ihandle -- str len )
  ?dup 0= if 0 0 then

  dup ihandle>phandle >dn.parent @ 0= if drop " /" exit then
    
  \ dictionary abused for temporary storage
  >r 0 0 here 40 + 
  begin r> dup >in.my-parent @ dup >r while
    ( path len tempbuf ihandle R: ihandle.parent )
    dup >in.interposed @ 0= if
      inodename rot tmpstrcat
      " /" rot tmpstrcat
    else
      drop
    then
  repeat
  r> 3drop
  pocket tmpstrcpy drop
;

\ used by client interface (instance-to-interposed-path)
: get-instance-interposed-path ( ihandle -- str len )
  ?dup 0= if 0 0 then

  dup ihandle>phandle >dn.parent @ 0= if drop " /" exit then
    
  \ dictionary abused for temporary storage
  >r 0 0 here 40 + 
  begin r> dup >in.my-parent @ dup >r while
    ( path len tempbuf ihandle R: ihandle.parent )
    dup >r inodename rot tmpstrcat
    r> >in.interposed @ if " /%" else " /" then
    rot tmpstrcat
  repeat
  r> 3drop
  pocket tmpstrcpy drop
;

: pwd    ( -- )
  ?active-package get-package-path type
;
  
: ls    ( -- )
  cr
  ?active-package >dn.child @
  begin dup while
    dup u. dup pnodename type cr
    >dn.peer @
  repeat
  drop
;
  

\ -------------------------------------------
\  property printing
\ -------------------------------------------

: .p-string? ( data len -- true | data len false )
  \ no trailing zero?
  2dup + 1- c@ if 0 exit then

  swap >r 0 
  \ count zeros and detect unprintable characters?
  over 1- begin 1- dup 0>= while
    dup r@ + c@
    ( len zerocnt n ch )

    ?dup 0= if
      swap 1+ swap
    else
      dup 1b <= swap 80 >= or
      if 2drop r> swap 0 exit then
    then
  repeat drop r> -rot
  ( data len zerocnt )
  
  \ simple string
  0= if
    ascii " emit 1- type ascii " emit true exit
  then

  \ make sure there are no double zeros (except possibly at the end)
  2dup over + swap
  ( data len end ptr )
  begin 2dup <> while
    dup c@ 0= if
      2dup 1+ <> if 2drop false exit then
    then
    dup cstrlen 1+ +
  repeat
  2drop
  
  ." {"
  0 -rot over + swap
  \ multistring ( cnt end ptr )
  begin 2dup <> while
    rot dup if ." , " then 1+ -rot
    dup cstrlen 2dup
    ascii " emit type ascii " emit
    1+ +
  repeat
  ." }"
  3drop true
;

: .p-int? ( data len -- 1 | data len 0 )
  dup 4 <> if false exit then
  decode-int -rot 2drop true swap
  dup 0>= if . exit then
  dup -ff < if u. exit then
  .
;

\ Print a number zero-padded
: 0.r ( u minlen -- )
  0 swap <# 1 ?do # loop #s #> type
;

: .p-bytes? ( data len -- 1 | data len 0 )
  ." -- " dup . ." : "
  swap >r 0
  begin 2dup > while
    dup r@ + c@
    ( len n ch )

    2 0.r space
    1+
  repeat 
  2drop r> drop 1
;

\ this function tries to heuristically determine the data format
: (.property) ( data len -- )
  dup 0= if 2drop ." <empty>" exit then

  .p-string? if exit then
  .p-int? if exit then
  .p-bytes? if exit then
  2drop ." <unimplemented type>"
;

\ Print the value of a property in "reg" format
: .p-reg ( #acells #scells data len -- )
  2dup + -rot ( #acells #scells data+len data len )
  >r >r -rot ( data+len #acells #scells  R: len data )
  4 * swap 4 * dup r> r> ( data+len #sbytes #abytes #abytes data len )
  bounds ( data+len #sbytes #abytes #abytes data+len data ) ?do
    dup 0= if 2 spaces then			\ start of "size" part
    2dup <> if						\ non-first byte in row
      dup 3 and 0= if space then	\ make numbers more readable
    then
    i c@ 2 0.r						\ print byte
    1- 3dup nip + 0= if				\ end of row
      3 pick i 1+ > if				\ non-last byte
        cr							\ start new line
        d# 26 spaces				\ indentation
      then
      drop dup						\ update counter
    then
  loop
  3drop drop
;

\ Return the number of cells per physical address
: .p-translations-#pacells ( -- #cells )
  " /" find-package if
    " #address-cells" rot get-package-property if
      1
    else
      decode-int nip nip 1 max
    then
  else
    1
  then
;

\ Return the number of cells per translation entry
: .p-translations-#cells ( -- #cells )
  [IFDEF] CONFIG_PPC
    my-#acells 3 *
    .p-translations-#pacells +
  [ELSE]
    my-#acells 3 *
  [THEN]
;

\ Set up column offsets
: .p-translations-cols ( -- col1 ... coln #cols )
  .p-translations-#cells 4 *
  [IFDEF] CONFIG_PPC
    4 -
    dup 4 -
    dup .p-translations-#pacells 4 * -
    3
  [ELSE]
    my-#acells 4 * -
    dup my-#scells 4 * -
    2
  [THEN]
;

\ Print the value of the MMU translations property
: .p-translations ( data len -- )
  >r >r .p-translations-cols r> r> ( col1 ... coln #cols data len )
  2dup + -rot ( col1 ... coln #cols data+len data len )
  >r >r .p-translations-#cells 4 * dup r> r>
  ( col1 ... coln #cols data+len #bytes #bytes len data )
  bounds ( col1 ... coln #cols data+len #bytes #bytes data+len data ) ?do
    3 pick 4 + 4 ?do				\ check all defined columns
      i pick over = if
        2 spaces					\ start new column
      then
    loop
    2dup <> if						\ non-first byte in row
      dup 3 and 0= if space then	\ make numbers more readable
    then
    i c@ 2 0.r						\ print byte
    1- dup 0= if					\ end of row
      2 pick i 1+ > if				\ non-last byte
        cr							\ start new line
        d# 26 spaces				\ indentation
      then
      drop dup						\ update counter
    then
  loop
  2drop drop 0 ?do drop loop
;

\ This function hardwires data formats to particular node properties
: (.property-by-name) ( name-str name-len data len -- )
  2over " reg" strcmp 0= if
    my-#acells my-#scells 2swap .p-reg
    2drop exit
  then

  active-package get-nodename " memory" strcmp 0= if
    2over " available" strcmp 0= if
      my-#acells my-#scells 2swap .p-reg
      2drop exit
    then
  then
  " /chosen" find-dev if
    " mmu" rot get-package-property 0= if
      decode-int nip nip ihandle>phandle active-package = if
        2over " available" strcmp 0= if
          my-#acells my-#scells 1 max 2swap .p-reg
          2drop exit
        then
        2over " translations" strcmp 0= if
          .p-translations
          2drop exit
        then
      then
    then
  then

  2swap 2drop ( data len )
  (.property)
;

: .properties    ( -- )
  ?active-package dup >r if
    0 0
    begin
      r@ next-property
    while
      cr 2dup dup -rot type
      begin ."  " 1+ dup d# 26 >= until drop
      2dup
      2dup active-package get-package-property drop
      ( name-str name-len data len )
      (.property-by-name)
    repeat
  then
  r> drop
  cr
;


\ 7.4.11    Device tree

: print-dev ( phandle -- phandle )
  dup u. 
  dup get-package-path type
  dup " device_type" rot get-package-property if
    cr 
  else
    ."  (" decode-string type ." )" cr 2drop
  then
  ;

: show-sub-devs ( subtree-phandle -- )
  print-dev
  >dn.child @
    begin dup while
      dup recurse
      >dn.peer @
    repeat
    drop
  ;

: show-all-devs    ( -- )
  active-package
  cr " /" find-device
  ?active-package show-sub-devs
  active-package!
  ;


: show-devs    ( "{device-specifier}<cr>" -- )
  active-package
  cr " /" find-device
  linefeed parse find-device
  ?active-package show-sub-devs
  active-package!
  ;



\ 7.4.11.3 Device probing

\ Set to true if the last probe-self was successful
0 value probe-fcode?

: probe-all    ( -- )
  ;
