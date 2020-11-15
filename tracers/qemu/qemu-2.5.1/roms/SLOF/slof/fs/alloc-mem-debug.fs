\ *****************************************************************************
\ * Copyright (c) 2011 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/
\ * Dynamic memory allocation/de-allocation debug functions
\ *****************************************************************************


\ Uncomment the following code for debugging bad write accesses beyond
\ the end of the allocated block:
\ Store magic value past the end of the block during alloc-mem and
\ check for this magic value when free-mem has been called.
#if 1
: alloc-mem  ( len -- addr )
   dup /n + alloc-mem    ( len addr )
   2dup + 3141592653589793 swap ! nip
;

: free-mem  ( addr len -- )
   2dup + @ 3141592653589793 <> IF
      cr ." Detected memory corrupt during free-mem of "
      swap . . cr EXIT
   THEN
   /n + free-mem
;
#endif


\ Never ever assume that allocated memory is pre-initialized with 0 ...
: alloc-mem  ( len -- addr )
   dup alloc-mem  swap 2dup ff fill drop
;

\ Make sure that memory block do not contain "valid" data after free-mem:
: free-mem  ( addr len -- )
   2dup ff fill  free-mem
;


\ The following definitions are used for debugging the parameters of free-mem:
\ Store block address and size of allocated blocks
\ in an array, then check for right values on free-mem.

1000 CONSTANT max-malloced-blocks
CREATE malloced-blocks max-malloced-blocks 2 * cells allot
malloced-blocks max-malloced-blocks 2 * cells erase


: alloc-mem  ( len -- addr )
   dup alloc-mem dup 0= IF
      cr ." alloc-mem returned 0 for size " swap . cr EXIT
   THEN                                        ( len addr )
   malloced-blocks max-malloced-blocks 0 DO    ( len addr m-blocks-ptr )
      dup @ 0= IF                              ( len addr m-blocks-ptr )
         \ Found a free entry: store addr and len
         over >r dup >r !
         r> cell+ !
         r> UNLOOP EXIT
      THEN
      cell+ cell+                              ( len addr next-m-blocks-ptr )
   LOOP
   ." Please increase max-malloced-blocks." cr ( len addr next-m-blocks-ptr )
   drop nip
;


: free-mem  ( addr len -- )
   malloced-blocks max-malloced-blocks 0 DO    ( addr len m-blocks-ptr )
      dup @ ?dup IF
         ( addr len m-blocks-ptr s-addr )
         3 pick = IF
            ( addr len m-blocks-ptr )
            dup cell+ @     ( addr len m-blocks-ptr s-len )
            2 pick = IF     ( addr len m-blocks-ptr )
               \ All right, addr and len matched,
               \ clear entry and call original free-mem.
               dup cell+ 0 swap !
               0 swap !
               free-mem 
            ELSE
               >r swap cr
               ." free-mem called for block " . ." with wrong size=" . cr
               ." ( correct size should be: " r> cell+ @ . ." )" cr
            THEN
            UNLOOP EXIT
         THEN                 ( addr len m-blocks-ptr )
      THEN
      cell+ cell+             ( addr len next-m-blocks-ptr )
   LOOP
   drop swap cr
   ." free-mem called for block " .
   ." ( size=" .
   ." ) which has never been allocated before!" cr
;


\ Enable these for verbose debug messages:
#if 0
: alloc-mem
   cr ." alloc-mem with len=" dup .
   alloc-mem
   ."  returned addr=" dup . cr
;

: free-mem
   cr ." free mem addr=" over . ."  len=" dup . cr
   free-mem
;
#endif
