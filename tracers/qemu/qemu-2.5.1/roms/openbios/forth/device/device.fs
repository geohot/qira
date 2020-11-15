\ tag: Package creation and deletion
\ 
\ this code implements IEEE 1275-1994 
\ 
\ Copyright (C) 2003, 2004 Samuel Rydh
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

variable device-tree

\ make defined words globally visible
\ 
: external ( -- )
  active-package ?dup if
    >dn.methods @ set-current
  then
;

\ make the private wordlist active (not an OF word)
\ 
: private ( -- )
  active-package ?dup if
    >r
    forth-wordlist r@ >dn.methods @ r@ >dn.priv-methods @ 3 set-order
    r> >dn.priv-methods @ set-current
  then
;

\ set activate package and make the world visible package wordlist
\ the current one.
\ 
: active-package! ( phandle -- )
  dup to active-package
  \ locally defined words are not available
  ?dup if
    forth-wordlist over >dn.methods @ 2 set-order
    >dn.methods @ set-current
  else
    forth-wordlist dup 1 set-order set-current
  then
;


\ new-device ( -- )
\ 
\ Start new package, as child of active package.
\ Create a new device node as a child of the active package and make the 
\ new node the active package. Create a new instance and make it the current
\ instance; the instance that invoked new-device becomes the parent instance 
\ of the new instance.
\ Subsequently, newly defined Forth words become the methods of the new node 
\ and newly defined data items (such as types variable, value, buffer:, and 
\ defer) are allocated and stored within the new instance.

: new-device ( -- )
  align-tree dev-node.size alloc-tree >r
  active-package
  dup r@ >dn.parent !

  \ ( parent ) hook up at the end of the peer list
  ?dup if
    >dn.child
    begin dup @ while @ >dn.peer repeat
    r@ swap !
  else
    \ we are the root node!
    r@ to device-tree
  then

  \ ( -- ) fill in device node stuff
  inst-node.size r@ >dn.isize !

  \ create two wordlists
  wordlist r@ >dn.methods !
  wordlist r@ >dn.priv-methods !
  
  \ initialize template data
  r@ >dn.itemplate
  r@ over >in.device-node !
  my-self over >in.my-parent !

  \ make it the active package and current instance
  to my-self
  r@ active-package!
  
  \ swtich to public wordlist
  external
  r> drop
;

\ helpers for finish-device (OF does not actually define words
\ for device node deletion)

: (delete-device) \ ( phandle )
  >r
  r@ >dn.parent @
  ?dup if
    >dn.child    \ ( &first-child )
    begin dup @ r@ <> while @ >dn.peer repeat
    r@ >dn.peer @ swap !
  else
    \ root node
    0 to device-tree
  then

  \ XXX: free any memory related to this node.
  \ we could have a list with free device-node headers...
  r> drop
;

: delete-device \ ( phandle )
  >r 
  \ first, get rid of any children
  begin r@ >dn.child @ dup while
    (delete-device)
  repeat
  drop
  
  \ then free this node
  r> (delete-device)
;

\ finish-device ( -- )
\ 
\ Finish this package, set active package to parent.
\ Complete a device node that was created by new-device, as follows: If the
\ device node has no "name" property, remove the device node from the device 
\ tree. Otherwise, save the current values of the current instance's 
\ initialized data items within the active package for later use in
\ initializing the data items of instances created from that node. In any 
\ case, destroy the current instance, make its parent instance the current
\ instance, and select the parent node of the device node just completed, 
\ making the parent node the active package again.

: finish-device \ ( -- )
  my-self
  dup >in.device-node @ >r
  >in.my-parent @ to my-self

  ( -- )
  r@ >dn.parent @ active-package!
  s" name" r@ get-package-property if
    \ delete the node (and any children)
    r@ delete-device
  else
    2drop
    \ node OK
  then
  r> drop
;


\ helper function which creates and initializes an instance.
\ open is not called. The current instance is not changed.
\ 
: create-instance ( phandle -- ihandle|0 )
  dup >dn.isize @ ['] alloc-mem catch if 2drop 0 exit then
  >r
  \ we need to save the size in order to be able to release it properly
  dup >dn.isize @ r@ >in.alloced-size !

  \ clear memory (we only need to clear the head; all other data is copied)
  r@ inst-node.size 0 fill
  
  ( phandle R: ihandle )

  \ instantiate data
  dup >dn.methods @ r@ instance-init
  dup >dn.priv-methods @ r@ instance-init

  \ instantiate 
  dup >dn.itemplate r@ inst-node.size move
  r@ r@ >in.instance-data !
  my-self r@ >in.my-parent !
  drop

  r>
;

\ helper function which tears down and frees an instance
: destroy-instance ( ihandle )
  ?dup if
    \ free arguments
    dup >in.arguments 2@ free-mem
    \ and the instance block
    dup >in.alloced-size @
    free-mem
  then
;

\ Redefine to word so that statements of the form "0 to active-package"
\ are supported for bootloaders that require it
: to
  ['] ' execute
  dup ['] active-package = if
    drop active-package!
  else
    (to-xt)
  then
; immediate
