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


\ Implementation of ACCEPT.  Using ECMA-48 for terminal control.

: beep  bell emit ;

: TABLE-EXECUTE
  CREATE DOES> swap cells+ @ ?dup IF execute ELSE beep THEN ;

0 VALUE accept-adr
0 VALUE accept-max
0 VALUE accept-len
0 VALUE accept-cur

: esc  1b emit ;
: csi  esc 5b emit ;

: move-cursor ( -- )
   esc ." 8" accept-cur IF
      csi base @ decimal accept-cur 0 .r base ! ." C"
   THEN
;

: redraw-line ( -- )
   accept-cur accept-len = IF EXIT THEN
   move-cursor
   accept-adr accept-len accept-cur /string type
   csi ." K" move-cursor
;

: full-redraw-line ( -- )
   accept-cur 0 to accept-cur move-cursor
   accept-adr accept-len type
   csi ." K" to accept-cur move-cursor
;

: redraw-prompt ( -- )
   cr depth . [char] > emit
;

: insert-char ( char -- )
   accept-len accept-max = IF drop beep EXIT THEN
   accept-cur accept-len <> IF csi ." @" dup emit
   accept-adr accept-cur + dup 1+ accept-len accept-cur - move
   ELSE dup emit THEN
   accept-adr accept-cur + c!
   accept-cur 1+ to accept-cur
   accept-len 1+ to accept-len redraw-line
;

: delete-char ( -- )
   accept-cur accept-len = IF beep EXIT THEN
   accept-len 1- to accept-len
   accept-adr accept-cur + dup 1+ swap accept-len accept-cur - move
   csi ." P" redraw-line
;

\ *
\ * History handling
\ *

STRUCT
cell FIELD his>next
cell FIELD his>prev
cell FIELD his>len
   0 FIELD his>buf
CONSTANT /his
0 VALUE his-head
0 VALUE his-tail
0 VALUE his-cur

: add-history ( -- )
   accept-len 0= IF EXIT THEN
   /his accept-len + alloc-mem
   his-tail IF dup his-tail his>next ! ELSE dup to his-head THEN
   his-tail over his>prev !  0 over his>next !  dup to his-tail
   accept-len over his>len !  accept-adr swap his>buf accept-len move
;

: history  ( -- )
   his-head BEGIN dup WHILE
   cr dup his>buf over his>len @ type
   his>next @ REPEAT drop
;

: select-history ( his -- )
   dup to his-cur dup IF
   dup his>len @ accept-max min dup to accept-len to accept-cur
   his>buf accept-adr accept-len move ELSE
   drop 0 to accept-len 0 to accept-cur THEN
   full-redraw-line
;


\
\ tab completion
\

\ tab completion state variables
0 value ?tab-pressed
0 value tab-last-adr
0 value tab-last-len

\ compares two strings and returns the longest equal substring.
: $same-string ( addr-1 len-1 addr-2 len-2 -- addr-1 len-1' )
   dup 0= IF    \ The second parameter is not a string.
      2drop EXIT \ bail out
   THEN
   rot min 0 0 -rot ( addr1 addr2 0 len' 0 )
   DO ( addr1 addr2 len-1' )
      2 pick i + c@ lcc
      2 pick i + c@ lcc
      = IF 1 + ELSE leave THEN
   LOOP
   nip
;

: $tab-sift-words    ( text-addr text-len -- sift-count )
   sift-compl-only >r true to sift-compl-only \ save sifting mode

   last BEGIN @ ?dup WHILE \ loop over all words
      $inner-sift IF \ any completions possible?
         \ convert to lower case for user interface sanity
         2dup bounds DO I c@ lcc I c! LOOP
         ?tab-pressed IF 2dup type space THEN  \ <tab><tab> prints possibilities
         tab-last-adr tab-last-len $same-string \ find matching substring ...
         to tab-last-len to tab-last-adr       \ ... and save it
      THEN
   repeat
   2drop

   #sift-count 0 to #sift-count	\ how many words were found?
   r> to sift-compl-only		\ restore sifting completion mode
;

\ 8< node sifting for tab completion on device tree nodes below this line 8<

#include <stack.fs>

10 new-stack device-stack

: (next-dev) ( node -- node' addr len )
   device-stack
   dup (node>path) rot
   dup child IF dup push child -rot EXIT THEN
   dup peer IF peer -rot EXIT THEN
   drop
   BEGIN
      stack-depth
   WHILE
      pop peer ?dup IF -rot EXIT THEN
   REPEAT
   0 -rot
;

: $inner-sift-nodes ( text-addr text-len node -- ... path-addr path-len true | false )
   (next-dev) ( text-addr text-len node' path-addr path-len )
   dup 0= IF drop false EXIT THEN
   2dup 6 pick 6 pick find-isubstr ( text-addr text-len node' path-addr path-len pos )
   0= IF
      #sift-count 1+ to #sift-count \ count completions
      true
   ELSE
      2drop false
   THEN
;

\
\ test function for (next-dev)
: .nodes ( -- )
   s" /" find-node BEGIN dup WHILE
      (next-dev)
      type cr
   REPEAT
   drop
   reset-stack
;

\ node sifting wants its own pockets
create sift-node-buffer 1000 allot
0 value sift-node-num
: sift-node-buffer
   sift-node-buffer sift-node-num 100 * +
   sift-node-num 1+ dup 10 = IF drop 0 THEN
   to sift-node-num
;

: $tab-sift-nodes    ( text-addr text-len -- sift-count )
   s" /" find-node BEGIN dup WHILE
      $inner-sift-nodes IF \ any completions possible?
         sift-node-buffer swap 2>r 2r@ move 2r> \ make an almost permanent copy without strdup
         ?tab-pressed IF 2dup type space THEN  \ <tab><tab> prints possibilities
         tab-last-adr tab-last-len $same-string \ find matching substring ...
         to tab-last-len to tab-last-adr       \ ... and save it
      THEN
   REPEAT
   2drop drop
   #sift-count 0 to #sift-count	\ how many words were found?
   reset-stack
;

: $tab-sift    ( text-addr text-len -- sift-count )
   ?tab-pressed IF beep space THEN \ cosmetical fix for <tab><tab>

   dup IF bl rsplit dup IF 2swap THEN ELSE 0 0 THEN >r >r

   0 dup to tab-last-len to tab-last-adr	\ reset last possible match
   current-node @ IF			\ if we are in a node?
      2dup 2>r				\ save text
      $tab-sift-words to #sift-count	\ search in current node first
      2r>				\ fetch text to complete, again
   THEN
   2dup 2>r
   current-node @ >r 0 set-node		\ now search in global words
   $tab-sift-words to #sift-count
   r> set-node
   2r> $tab-sift-nodes
   \ concatenate previous commands
   r> r> dup IF s"  " $cat THEN tab-last-adr tab-last-len $cat
   to tab-last-len to tab-last-adr  \ ... and save the whole string
;

\ 8< node sifting for tab completion on device tree nodes above this line 8<

: handle-^A
   0 to accept-cur move-cursor ;
: handle-^B
   accept-cur ?dup IF 1- to accept-cur ( csi ." D" ) move-cursor THEN ;
: handle-^D
   delete-char ( redraw-line ) ;
: handle-^E
   accept-len to accept-cur move-cursor ;
: handle-^F
   accept-cur accept-len <> IF accept-cur 1+ to accept-cur csi ." C" THEN ;
: handle-^H
   accept-cur 0= IF beep EXIT THEN
   handle-^B delete-char
;
: handle-^I
   accept-adr accept-len
   $tab-sift 0 > IF
      ?tab-pressed IF
         redraw-prompt full-redraw-line
         false to ?tab-pressed
      ELSE
         tab-last-adr accept-adr tab-last-len move    \ copy matching substring
         tab-last-len dup to accept-len to accept-cur \ len and cursor position
         full-redraw-line		\ redraw new string
         true to ?tab-pressed	\ second tab will print possible matches
      THEN
   THEN
;

: handle-^K
   BEGIN accept-cur accept-len <> WHILE delete-char REPEAT ;
: handle-^L
   history redraw-prompt full-redraw-line ;
: handle-^N
   his-cur IF his-cur his>next @ ELSE his-head THEN
   dup to his-cur select-history
;
: handle-^P
   his-cur IF his-cur his>prev @ ELSE his-tail THEN
   dup to his-cur select-history
;
: handle-^Q  \ Does not handle terminal formatting yet.
   key insert-char ;
: handle-^R
   full-redraw-line ;
: handle-^U
   0 to accept-len 0 to accept-cur full-redraw-line ;

: handle-fn
   key drop beep
;

TABLE-EXECUTE handle-CSI
0 , ' handle-^P , ' handle-^N , ' handle-^F ,
' handle-^B , 0 , 0 , 0 ,
' handle-^A , 0 , 0 , ' handle-^E ,
0 , 0 , 0 , 0 ,
0 , 0 , 0 , 0 ,
0 , 0 , 0 , 0 ,
0 , 0 , 0 , 0 ,
0 , 0 , 0 , 0 ,

TABLE-EXECUTE handle-meta
0 , 0 , 0 , 0 ,
0 , 0 , 0 , 0 ,
0 , 0 , 0 , 0 ,
0 , 0 , 0 , ' handle-fn ,
0 , 0 , 0 , 0 ,
0 , 0 , 0 , 0 ,
0 , 0 , 0 , ' handle-CSI ,
0 , 0 , 0 , 0 ,

: handle-ESC-O
   key
   dup 48 = IF
      handle-^A
   ELSE
      dup 46 = IF
         handle-^E
      THEN
   THEN drop
;

: handle-ESC-5b
   key
   dup 31 = IF \ HOME
      key drop ( drops closing 7e ) handle-^A
   ELSE
      dup 33 = IF \ DEL
         key drop handle-^D
      ELSE
         dup 34 = IF \ END
            key drop handle-^E
         ELSE
            dup 1f and handle-CSI
         THEN
      THEN
   THEN drop
;

: handle-ESC
   key
   dup 5b = IF
      handle-ESC-5b
   ELSE
      dup 4f = IF
         handle-ESC-O
      ELSE
         dup 1f and handle-meta
      THEN
   THEN drop
;

TABLE-EXECUTE handle-control
0 , \ ^@:
' handle-^A ,
' handle-^B ,
0 , \ ^C:
' handle-^D ,
' handle-^E ,
' handle-^F ,
0 , \ ^G:
' handle-^H ,
' handle-^I , \ tab
0 , \ ^J:
' handle-^K ,
' handle-^L ,
0 , \ ^M: enter: handled in main loop
' handle-^N ,
0 , \ ^O:
' handle-^P ,
' handle-^Q ,
' handle-^R ,
0 , \ ^S:
0 , \ ^T:
' handle-^U ,
0 , \ ^V:
0 , \ ^W:
0 , \ ^X:
0 , \ ^Y: insert save buffer
0 , \ ^Z:
' handle-ESC ,
0 , \ ^\:
0 , \ ^]:
0 , \ ^^:
0 , \ ^_:

: (accept) ( adr len -- len' )
   cursor-on
   to accept-max to accept-adr
   0 to accept-len 0 to accept-cur
   0 to his-cur
   1b emit 37 emit
   BEGIN
      key dup 0d <>
   WHILE
      dup 9 <> IF 0 to ?tab-pressed THEN \ reset state machine
      dup 7f = IF drop 8 THEN \ Handle DEL as if it was BS. ??? bogus
      dup bl < IF handle-control ELSE
         dup 80 and IF
            dup a0 < IF 7f and handle-meta ELSE drop beep THEN
         ELSE
            insert-char
	 THEN
      THEN
   REPEAT
   drop add-history
   accept-len to accept-cur
   move-cursor space
   accept-len
   cursor-off
;

' (accept) to accept

