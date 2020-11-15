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


100 CONSTANT quiesce-xt#

\ The array with the quiesce execution tokens:
CREATE quiesce-xts quiesce-xt# cells allot
quiesce-xts quiesce-xt# cells erase

0 VALUE quiesce-done?


\ Add a token to the quiesce execution token array:
: add-quiesce-xt  ( xt -- )
   quiesce-xt# 0 DO
      quiesce-xts I cells +    ( xt arrayptr )
      dup @ 0=                 ( xt arrayptr true|false )
      IF
         ! UNLOOP EXIT
      ELSE                     ( xt arrayptr )
         over swap             ( xt xt arrayptr )
         @ =                   \ xt already stored ?
         IF
            drop UNLOOP EXIT
         THEN                  ( xt )
      THEN
   LOOP
   drop                        ( xt -- )
   ." Warning: quiesce xt list is full." cr
;


\ The quiesce call asserts that the firmware and all hardware
\ is in a sane state (e.g. assert that no background DMA is
\ running anymore)
: quiesce  ( -- )
   quiesce-done? IF EXIT THEN
   true to quiesce-done?
   quiesce-xt# 0 DO
      quiesce-xts I cells +    ( arrayptr )
      @ dup IF                 ( xt )
         EXECUTE
      ELSE
         drop UNLOOP EXIT
      THEN
   LOOP
;

