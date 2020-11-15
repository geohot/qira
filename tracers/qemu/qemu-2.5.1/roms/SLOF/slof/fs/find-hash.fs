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

#ifdef HASH_DEBUG
0 value from-hash
0 value not-from-hash
0 value hash-collisions
#endif

clean-hash

: hash-find ( str len head -- 0 | link )
   >r 2dup 2dup hash                  ( str len str len hash          R: head )
   dup >r @ dup                       ( str len str len *hash *hash   R: head hash )
   IF                                 ( str len str len *hash         R: head hash )
      link>name name>string string=ci ( str len true|false            R: head hash )
      dup 0=
      IF
#ifdef HASH_DEBUG
         hash-collisions 1+
         to hash-collisions
#endif
      THEN
   ELSE
      nip nip                         ( str len 0                     R: head hash )
   THEN
   IF                                 \ hash found
      2drop r> @ r> drop              (  *hash                        R: )
#ifdef HASH_DEBUG
      from-hash 1+ to from-hash
#endif
      exit
   THEN                               \ hash not found
   r> r> swap >r ((find))             ( str len head                  R: hash=0 )
   dup
   IF
#ifdef HASH_DEBUG
      not-from-hash 1+
      to not-from-hash
#endif
      dup r> !                        ( link                          R: )
   ELSE
      r> drop                         ( 0                             R: )
   THEN
;

: hash-reveal  hash off ;

' hash-reveal to (reveal)
' hash-find to (find)

#ifdef HASH_DEBUG
\ print out all entries in the hash table
: dump-hash-table  ( -- )
   cr
   hash-table hash-size 0  DO
      dup @ dup 0<>  IF
         over . s" : " type link>name name>string type cr
      ELSE
         drop
      THEN
      cell+
   LOOP drop
   s" hash-collisions: " type hash-collisions . cr
   s" from-hash: " type from-hash . cr
   s" not-from-hash: " type not-from-hash . cr
;
#endif
