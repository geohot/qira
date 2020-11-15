\ *****************************************************************************
\ * Copyright (c) 2004, 2011 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ Support for device node instances.

0 VALUE my-self

400 CONSTANT max-instance-size

STRUCT
   /n FIELD instance>node
   /n FIELD instance>parent
   /n FIELD instance>args
   /n FIELD instance>args-len
   /n FIELD instance>size
   /n FIELD instance>#units
   /n FIELD instance>unit1          \ For instance-specific "my-unit"
   /n FIELD instance>unit2
   /n FIELD instance>unit3
   /n FIELD instance>unit4
CONSTANT /instance-header

: >instance  ( offset -- myself+offset )
   my-self 0= ABORT" No instance!"
   dup my-self instance>size @ >= ABORT" Instance access out of bounds!"
   my-self +
;

: (create-instance-var) ( initial-value -- )
   get-node
   dup node>instance-size @ cell+ max-instance-size
   >= ABORT" Instance is bigger than max-instance-size!"
   dup node>instance-template @      ( iv phandle tmp-ih )
   swap node>instance-size dup @     ( iv tmp-ih *instance-size instance-size )
   dup ,                             \ compile current instance ptr
   swap 1 cells swap +!              ( iv tmp-ih instance-size )
   + !
;

: create-instance-var ( "name" initial-value -- )
   CREATE (create-instance-var) PREVIOUS
;

: (create-instance-buf) ( buffersize -- )
   aligned                               \ align size to multiples of cells
   dup get-node node>instance-size @ +   ( buffersize' newinstancesize )
   max-instance-size > ABORT" Instance is bigger than max-instance-size!"
   get-node node>instance-template @  get-node node>instance-size @ +
   over erase                            \ clear according to IEEE 1275
   get-node node>instance-size @         ( buffersize' old-instance-size )
   dup ,                                 \ compile current instance ptr
   + get-node node>instance-size !       \ store new size
;

: create-instance-buf ( "name" buffersize -- )
   CREATE (create-instance-buf) PREVIOUS
;

VOCABULARY instance-words  ALSO instance-words DEFINITIONS

: VARIABLE  0 create-instance-var DOES> [ here ] @ >instance ;
: VALUE       create-instance-var DOES> [ here ] @ >instance @ ;
: DEFER     0 create-instance-var DOES> [ here ] @ >instance @ execute ;
: BUFFER:     create-instance-buf DOES> [ here ] @ >instance ;

PREVIOUS DEFINITIONS

\ Save XTs of the above instance-words (put on the stack with "[ here ]")
CONSTANT <instancebuffer>
CONSTANT <instancedefer>
CONSTANT <instancevalue>
CONSTANT <instancevariable>

\ check whether a value or a defer word is an
\ instance word: It must be a CREATE word and
\ the DOES> part must do >instance as first thing

: (instance?) ( xt -- xt true|false )
   dup @ <create> = IF
      dup cell+ @ cell+ @ ['] >instance =
   ELSE
      false
   THEN
;

\ This word does instance values in compile mode.
\ It corresponds to DOTO from engine.in
: (doito) ( value R:*CFA -- )
   r> cell+ dup >r
   @ cell+ cell+ @ >instance !
;
' (doito) CONSTANT <(doito)>

: to ( value wordname<> -- )
   ' (instance?)
   state @ IF
      \ compile mode handling normal or instance value
      IF ['] (doito) ELSE ['] DOTO THEN
      , , EXIT
   THEN
   IF
      cell+ cell+ @ >instance ! \ interp mode instance value
   ELSE
      cell+ !                   \ interp mode normal value
   THEN
; IMMEDIATE

: behavior  ( defer-xt -- contents-xt )
   dup cell+ @ <instancedefer> = IF   \ Is defer-xt an INSTANCE DEFER ?
      2 cells + @ >instance @
   ELSE
      behavior
   THEN
;

: INSTANCE  ALSO instance-words ;

: my-parent  my-self instance>parent @ ;
: my-args    my-self instance>args 2@ swap ;

\ copy args from original instance to new created
: set-my-args   ( old-addr len -- )
   dup IF                             \ IF len > 0                    ( old-addr len )
      dup alloc-mem                   \ | allocate space for new args ( old-addr len new-addr )
      2dup my-self instance>args 2!   \ | write into instance struct  ( old-addr len new-addr )
      swap move                       \ | and copy the args           ( )
   ELSE                               \ ELSE                          ( old-addr len )
      my-self instance>args 2!        \ | set new args to zero, too   ( )
   THEN                               \ FI
;

\ Current node has already been set, when this is called.
: create-instance-data ( -- instance )
   get-node dup node>instance-template @    ( phandle instance-template )
   swap node>instance-size @                ( instance-template instance-size )
   dup >r
   dup alloc-mem dup >r swap move r>        ( instance )
   dup instance>size r> swap !              \ Store size for destroy-instance
   dup instance>#units 0 swap !             \ Use node unit by default
;
: create-instance ( -- )
   my-self create-instance-data
   dup to my-self instance>parent !
   get-node my-self instance>node !
;

: destroy-instance ( instance -- )
   dup instance>args @ ?dup IF               \ Free instance args?
      over instance>args-len @  free-mem
   THEN
   dup instance>size @  free-mem
;

: ihandle>phandle ( ihandle -- phandle )
   dup 0= ABORT" no current instance" instance>node @
;

: push-my-self ( ihandle -- )  r> my-self >r >r to my-self ;
: pop-my-self ( -- )  r> r> to my-self >r ;
: call-package  push-my-self execute pop-my-self ;
: $call-static ( ... str len node -- ??? )
\  cr ." call for " 3dup -rot type ."  on node " .
   find-method IF execute ELSE -1 throw THEN
;

: $call-my-method  ( str len -- )
   my-self ihandle>phandle $call-static
;

: $call-method  ( str len ihandle -- )
   push-my-self
   ['] $call-my-method CATCH ?dup IF
      pop-my-self THROW
   THEN
   pop-my-self
;

0 VALUE calling-child

: $call-parent
   my-self ihandle>phandle TO calling-child
   my-parent $call-method
   0 TO calling-child
;
