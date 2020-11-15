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

\ ( ioapic-addr -- )
\ IO-APIC setup.

CONSTANT ioapic

: ioapic@  ( offset -- x )  ioapic rb! ioapic 10 + rl@-le ;
: ioapic!  ( x offset -- )  ioapic rb! ioapic 10 + rl!-le ;

: init-ioapic  ( irq# -- )
   1a000 or 1 ioapic@ 10 rshift 1+ 0  ?DO
      0 i 2* 11 + ioapic! dup
      \ move all ISA IRQs to 40 and higher,
      \ as to not conflict with U3/U4 internal
      \ IRQs. ISA IRQs are positive edge.
      dup ff and 0c <  IF  a000 - 40 +  THEN
      i 2* 10 + ioapic! 1+  LOOP  drop
;

: dump-ioapic  ( -- )
   1 ioapic@ 10 rshift 1+
   dup cr . ." irqs" 0  ?DO
      cr i 2 0.r space i 2* 11 + ioapic@ 8 0.r
      i 2* 10 + ioapic@ 8 0.r  LOOP
;
