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

\ Claim memory for segment
\ Abort, if no memory available

false value elf-claim?
0     value last-claim

\ cur-brk is set by elf loader to end of data segment
0 VALUE cur-brk


: elf-claim-segment ( addr size -- errorcode )
   2dup
   elf-claim? IF
      >r
      here last-claim , to last-claim                \ Setup ptr to last claim
      \ Put addr and size in the data space
      dup , r> dup , ( addr size )
      0 ['] claim CATCH IF
         ." Memory for ELF file is already in use!" cr
         true ABORT" Memory for ELF file already in use "
      THEN
      drop
   ELSE
      2drop
   THEN
   + to cur-brk
   0 
;


\ Load ELF file and claim the corresponding memory regions.
\ A destination address can be specified. If the parameter is -1 then
\ the file is loaded to the ddress that is specified in its header.
: elf-load-claim ( file-addr destaddr -- claim-list entry imagetype )
   true to elf-claim?
   0 to last-claim
   dup -1 = IF             \ If destaddr == -1 then load to addr from ELF header
      drop ['] elf-load-file CATCH IF false to elf-claim? ABORT THEN
   ELSE
      ['] elf-load-file-to-addr CATCH IF false to elf-claim? ABORT THEN
   THEN
   >r
   last-claim swap
   false to elf-claim?
   r>
;


\ Release memory claimed before

: elf-release ( claim-list -- )
   BEGIN
      dup cell+                   ( claim-list claim-list-addr )
      dup @ swap cell+ @          ( claim-list claim-list-addr claim-list-sz )
      release                     ( claim-list )
      @ dup 0=                    ( Next-element )
   UNTIL
   drop
;
