\ *****************************************************************************
\ * Copyright (c) 2004, 2008 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/


\ Properties 5.3.5

\ Words on the property list for a node are actually executable words,
\ that return the address and length of the property's data.  Special
\ nodes like /options can have their properties use specialized code to
\ dynamically generate their data; most nodes just use a 2CONSTANT.

\ Put the type as byte before the property
\   { int = 1, bytes = 2, string = 3 }
\ This is used by .properties for pretty print

\ Flag for type encoding, encode-* resets, set-property set the flag
true value encode-first?

: decode-int  over >r 4 /string r> 4c@ swap 2swap swap bljoin ;
: decode-64 decode-int -rot decode-int -rot 2swap swap lxjoin ;
: decode-string ( prop-addr1 prop-len1 -- prop-addr2 prop-len2 str len )
   dup 0= IF 2dup EXIT THEN \ string properties with zero length
   over BEGIN dup c@ 0= IF 1+ -rot swap 2 pick over - rot over - -rot 1-
    EXIT THEN 1+ AGAIN ;

\ Remove a word from a wordlist.
: (prune) ( name len head -- )
  dup >r (find) ?dup IF r> BEGIN dup @ WHILE 2dup @ = IF
  >r @ r> ! EXIT THEN @ REPEAT 2drop ELSE r> drop THEN ;
: prune ( name len -- )  last (prune) ;

: set-property ( data dlen name nlen phandle -- )
    true to encode-first?
    get-current >r  node>properties @ set-current
    2dup prune  $2CONSTANT  r> set-current ;
: delete-property ( name nlen -- )
    get-node get-current >r  node>properties @ set-current
    prune r> set-current ;
: property ( data dlen name nlen -- )  get-node set-property ;
: get-property ( str len phandle -- true | data dlen false )
  ?dup 0= IF cr cr cr ." get-property for " type ."  on zero phandle"
  cr cr true EXIT THEN
  node>properties @ voc-find dup IF link> execute false ELSE drop true THEN ;
: get-package-property ( str len phandle -- true | data dlen false )
  get-property ;
: get-my-property ( str len -- true | data dlen false )
  my-self ihandle>phandle get-property ;
: get-parent-property ( str len -- true | data dlen false )
  my-parent ihandle>phandle get-property ;

: get-inherited-property ( str len -- true | data dlen false )
   my-self ihandle>phandle
   BEGIN
      3dup get-property 0= IF
         \ Property found
         rot drop rot drop rot drop false EXIT
      THEN
      parent dup 0= IF
         \ Root node has been reached, but property has not been found
         3drop true EXIT
      THEN
   AGAIN
;

\ Print out properties.

20 CONSTANT indent-prop

: .prop-int ( str len -- )
   space
   400 min 0
   ?DO
      i over + dup                                 ( str act-addr act-addr )
      c@ 2 0.r 1+ dup c@ 2 0.r 1+ dup c@ 2 0.r 1+ c@ 2 0.r ( str )
      i c and c = IF                           \ check for multipleof 16 bytes
	 cr indent @ indent-prop + 1+ 0        \ linefeed + indent
	 DO
	    space                              \ print spaces
	 LOOP
      ELSE
	 space space                           \ print two spaces
      THEN
   4 +LOOP
   drop
;

: .prop-bytes ( str len -- )
   2dup -4 and .prop-int                       ( str len )

   dup 3 and dup IF                            ( str len len%4 )
      >r -4 and + r>                           ( str' len%4 )
      bounds                                   ( str' str'+len%4 )
      DO
	 i c@ 2 0.r                            \ Print last 3 bytes
      LOOP
   ELSE
      3drop
   THEN
;

: .prop-string ( str len )
   2dup space type
   cr indent @ indent-prop + 0 DO space LOOP   \ Linefeed
   .prop-bytes
;

: .propbytes ( xt -- )
   execute dup
   IF
      over cell- @ execute
   ELSE
      2drop
   THEN
;
: .property ( lfa -- )
    cr indent @ 0
    ?DO
	space
    LOOP
    link> dup >name name>string 2dup type nip ( len )
    indent-prop swap -                        ( xt 20-len )
    dup 0< IF drop 0 THEN 0                   ( xt number-of-space 0 )
    ?DO
	space
    LOOP
    .propbytes
;
: (.properties) ( phandle -- )
  node>properties @ cell+ @ BEGIN dup WHILE dup .property @ REPEAT drop ;
: .properties ( -- )
  get-node (.properties) ;

: next-property ( str len phandle -- false | str' len' true )
  ?dup 0= IF device-tree @ THEN  \ XXX: is this line required?
  node>properties @
  >r 2dup 0= swap 0= or IF 2drop r> cell+ ELSE r> voc-find THEN
  @ dup IF link>name name>string true THEN ;


\ encode-* words and all helpers

\ Start a encoded property string
: encode-start ( -- prop 0 )
   ['] .prop-int compile,
   false to encode-first?
   here 0
;

: encode-int ( val -- prop prop-len )
   encode-first? IF
      ['] .prop-int compile,             \ Execution token for print
      false to encode-first?
   THEN
   here swap lbsplit c, c, c, c, /l
;
: encode-bytes ( str len -- prop-addr prop-len )
   encode-first? IF
      ['] .prop-bytes compile,           \ Execution token for print
      false to encode-first?
   THEN
   here over 2dup 2>r allot swap move 2r>
;
: encode-string ( str len -- prop-addr prop-len )
   encode-first? IF
      ['] .prop-string compile,          \ Execution token for print
      false to encode-first?
   THEN
   encode-bytes 0 c, char+
;

: encode+ ( prop1-addr prop1-len prop2-addr prop2-len -- prop-addr prop-len )
   nip + ;
: encode-int+  encode-int encode+ ;
: encode-64    xlsplit encode-int rot encode-int+ ;
: encode-64+   encode-64 encode+ ;


\ Helpers for common nodes.  Should perhaps remove "compatible", as it's
\ not typically a single string.
: device-name  encode-string s" name"        property ;
: device-type  encode-string s" device_type" property ;
: model        encode-string s" model"       property ;
: compatible   encode-string s" compatible"  property ;
