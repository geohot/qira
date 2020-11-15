\ tag: Useful device related functions
\ 
\ Copyright (C) 2003, 2004 Samuel Rydh
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 


: parent ( phandle -- parent.phandle|0 )
  >dn.parent @
;

\ -------------------------------------------------------------------
\ property helpers
\ -------------------------------------------------------------------

: int-property ( value name-str name-len -- )
	rot encode-int 2swap property
;

\ -------------------------------------------------------------------------
\ property utils
\ -------------------------------------------------------------------------

\ like property (except it takes a phandle as an argument)
: encode-property ( buf len propname propname-len phandle -- )
	dup 0= abort" null phandle"

  my-self >r 0 to my-self
  active-package >r active-package!

  property

  r> active-package!
  r> to my-self
;

\ -------------------------------------------------------------------
\ device tree iteration
\ -------------------------------------------------------------------

: iterate-tree ( phandle -- phandle|0 )
  ?dup 0= if device-tree @ exit then

  \ children first
  dup child if
    child exit
  then

  \ then peers
  dup peer if
    peer exit
  then

  \ then peer of a parent
  begin >dn.parent @ dup while
    dup peer if peer exit then
  repeat
;

: iterate-tree-begin ( -- first_node )
  device-tree @
;


\ -------------------------------------------------------------------
\ device tree iteration
\ -------------------------------------------------------------------

: iterate-device-type ( lastph|0 type-str type-len -- 0|nextph )
  rot
  begin iterate-tree ?dup while
    >r
    2dup " device_type" r@ get-package-property if 0 0 then
    dup 0> if 1- then
    strcmp 0= if 2drop r> exit then
    r>
  repeat
  2drop 0
;

\ -------------------------------------------------------------------
\ device tree "cut and paste"
\ -------------------------------------------------------------------

\ add a subtree to the current device node
: link-nodes ( phandle -- )
  \ reparent phandle and peers
  dup begin ?dup while
    dup >dn.parent active-package !
    >dn.peer @
  repeat

  \ add to list of children
  active-package >dn.child
  begin dup @ while @ >dn.peer repeat dup . !
;

: link-node ( phandle -- )
  0 over >dn.peer !
  link-nodes
;
