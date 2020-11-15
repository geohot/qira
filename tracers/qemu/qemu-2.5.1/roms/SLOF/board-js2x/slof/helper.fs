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

: slof-build-id  ( -- str len )
   flash-header 10 + a
;

: slof-revision s" 001" ;

: read-version-and-date
   flash-header 0= IF
   s"  " encode-string
   ELSE
   flash-header 10 + 10
   here swap rmove
   here 10
   s" , " $cat
   bdate2human $cat encode-string THEN
;

: invert-region ( addr len -- )
   2dup or 7 and CASE
      0 OF 3 rshift 0 ?DO dup dup rx@ -1 xor swap rx! xa1+ LOOP ENDOF
      4 OF 2 rshift 0 ?DO dup dup rl@ -1 xor swap rl! la1+ LOOP ENDOF
      3 and
      2 OF 1 rshift 0 ?DO dup dup rw@ -1 xor swap rw! wa1+ LOOP ENDOF
      dup OF 0 ?DO dup dup rb@ -1 xor swap rb! 1+ LOOP ENDOF
   ENDCASE
   drop
;
