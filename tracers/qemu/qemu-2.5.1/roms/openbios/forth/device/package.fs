\ tag: Package access.
\ 
\ this code implements IEEE 1275-1994 ch. 5.3.4
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

\ variable last-package 0 last-package !
\ 0 value active-package
: current-device active-package ;
  
\ 
\ 5.3.4.1 Open/Close packages (part 1)
\ 

\ 0 value my-self ( -- ihandle )
: ?my-self
  my-self dup 0= abort" no current instance."
  ;

: my-parent ( -- ihandle )
  ?my-self >in.my-parent @
;

: ihandle>non-interposed-phandle ( ihandle -- phandle )
  begin dup >in.interposed @ while
    >in.my-parent @
  repeat
  >in.device-node @
;

: ihandle>phandle ( ihandle -- phandle )
  >in.device-node @
;


\ next-property
\ defined in property.c

: peer ( phandle -- phandle.sibling )
  ?dup if
    >dn.peer @
  else
    device-tree @
  then
;

: child ( phandle.parent -- phandle.child )
  \ Assume phandle == 0 indicates root node (not documented but similar
  \ behaviour to "peer"). Used by some versions of Solaris (e.g. 9).
  ?dup if else device-tree @ then

  >dn.child @
;
  

\ 
\ 5.3.4.2 Call methods from other packages
\ 

: find-method ( method-str method-len phandle -- false | xt true )
  \ should we search the private wordlist too? I don't think so...
  >dn.methods @ find-wordlist if
    true
  else
    2drop false
  then
;

: call-package ( ... xt ihandle -- ??? )
  my-self >r 
  to my-self
  execute
  r> to my-self
;


: $call-method  ( ... method-str method-len ihandle -- ??? )
  dup >r >in.device-node @ find-method if
    r> call-package
  else
    -21 throw
  then
;

: $call-parent  ( ... method-str method-len -- ??? )
  my-parent $call-method
;


\ 
\ 5.3.4.1 Open/Close packages (part 2)
\ 

\ find-dev ( dev-str dev-len -- false | phandle true )
\ find-rel-dev ( dev-str dev-len phandle -- false | phandle true )
\ 
\ These function works just like find-device but without
\ any side effects (or exceptions).
\ 
defer find-dev

: find-rel-dev ( dev-str dev-len phandle -- false | phandle true )
  active-package >r active-package!
  find-dev
  r> active-package!
;

: find-package  ( name-str name-len -- false | phandle true )
\ Locate the support package named by name string.
\ If the package can be located, return its phandle and true; otherwise, 
\ return false.
\ Interpret the name in name string relative to the "packages" device node.
\ If there are multiple packages with the same name (within the "packages" 
\ node), return the phandle for the most recently created one.

  \ This does the full path resolution stuff (including
  \ alias expansion. If we don't want that, then we should just
  \ iterade the children of /packages.
  " /packages" find-dev 0= if 2drop false exit then
  find-rel-dev 0= if false exit then

  true
;

: open-package  ( arg-str arg-len phandle -- ihandle | 0 )
\ Open the package indicated by phandle.
\ Create an instance of the package identified by phandle, save in that 
\ instance the instance-argument specified by arg-string and invoke the 
\ package's open method.
\ Return the instance handle ihandle of the new instance, or 0 if the package
\ could not be opened. This could occur either because that package has no
\ open method, or because its open method returned false, indicating an error.
\ The parent instance of the new instance is the instance that invoked
\ open-package. The current instance is not changed.

  create-instance dup 0= if
    3drop 0 exit
  then
  >r

  \ clone arg-str
  strdup r@ >in.arguments 2!

  \ open the package
  " open" r@ ['] $call-method catch if 3drop false then
  if
    r>
  else
    r> destroy-instance false
  then
;


: $open-package ( arg-str arg-len name-str name-len -- ihandle | 0 )
  \ Open the support package named by name string.
  find-package if
    open-package
  else 
    2drop false 
  then
;


: close-package ( ihandle -- )
\  Close the instance identified by ihandle by calling the package's close
\  method and then destroying the instance.
  dup " close" rot ['] $call-method catch if 3drop then
  destroy-instance
;

\ 
\ 5.3.4.3 Get local arguments
\ 

: my-address ( -- phys.lo ... )
  ?my-self >in.device-node @
  >dn.probe-addr
  my-#acells tuck /l* + swap 1- 0
  ?do
    /l - dup l@ swap
  loop
  drop
  ;
  
: my-space ( -- phys.hi )
  ?my-self >in.device-node @
  >dn.probe-addr @
  ;
  
: my-unit ( -- phys.lo ... phys.hi )
  ?my-self >in.my-unit
  my-#acells tuck /l* + swap 0 ?do
    /l - dup l@ swap
  loop
  drop
  ;

: my-args ( -- arg-str arg-len )
  ?my-self >in.arguments 2@
  ;

\ char is not included. If char is not found, then R-len is zero
: left-parse-string ( str len char -- R-str R-len L-str L-len )
  left-split
;

\ parse ints "hi,...,lo" separated by comma
: parse-ints ( str len num -- val.lo .. val.hi )
  -rot 2 pick -rot
  begin
    rot 1- -rot 2 pick 0>=
  while
    ( num n str len )
    2dup ascii , strchr ?dup if
      ( num n str len p )
      1+ -rot
      2 pick 2 pick -    ( num n p str len len1+1 )
      dup -rot -         ( num n p str len1+1 len2 )
      -rot 1-            ( num n p len2 str len1 )
    else
      0 0 2swap
    then
    $number if 0 then >r
  repeat
  3drop

  ( num ) 
  begin 1- dup 0>= while r> swap repeat
  drop
;
 
: parse-2int ( str len -- val.lo val.hi )
  2 parse-ints
;

  
\ 
\ 5.3.4.4 Mapping tools
\ 

: map-low ( phys.lo ... size -- virt )
  my-space swap s" map-in" $call-parent
  ;

: free-virtual ( virt size -- )
  over s" address" get-my-property 0= if
    decode-int -rot 2drop = if
      s" address" delete-property
    then
  else
    drop
  then
  s" map-out" $call-parent
  ;


\ Deprecated functions (required for compatibility with older loaders)

variable package-stack-pos 0 package-stack-pos !
create package-stack 8 cells allot

: push-package    ( phandle -- )
  \ Throw an error if we attempt to push a full stack
  package-stack-pos @ 8 >= if
    ." cannot push-package onto full stack" cr
    -99 throw
  then
  active-package
  package-stack-pos @ /n * package-stack + !
  package-stack-pos @ 1 + package-stack-pos !
  active-package!
  ;

: pop-package    ( -- )
  \ Throw an error if we attempt to pop an empty stack
  package-stack-pos @ 0 = if
    ." cannot pop-package from empty stack" cr
    -99 throw
  then
  package-stack-pos @ 1 - package-stack-pos !
  package-stack-pos @ /n * package-stack + @
  active-package!
  ;
