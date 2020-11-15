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


\ Example:
\
\ To get a 30 element stack, go:
\
\ 0 > 30 new-stack my-stack
\ 0 > my-stack
\ 0 > 20 push 30 push
\ 0 > pop pop .s

0 value current-stack

: new-stack ( cells <>name -- )
   create >r here    ( here R: cells )
   dup r@ 2 + cells  ( here here bytes R: cells )
   dup allot erase   ( here R: cells)
   cell+ r>          ( here+1cell cells )
   swap !            ( )
   DOES> to current-stack
;

: reset-stack ( -- )
   0 current-stack !
;

: stack-depth ( -- depth )
   current-stack @
;

: push ( value -- )
   current-stack @
   current-stack cell+ @ over <= ABORT" Stack overflow"
   cells
   1 current-stack +!
   current-stack 2 cells + + !
;

: pop ( -- value )
   current-stack @ 0= ABORT" Stack underflow"
   current-stack @ cells
   current-stack + cell+ @
   -1 current-stack +!
;


