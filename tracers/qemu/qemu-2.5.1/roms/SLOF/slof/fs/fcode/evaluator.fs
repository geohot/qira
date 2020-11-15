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


variable ip
variable fcode-end 
variable fcode-num
 1 value fcode-spread
 2 value fcode-offset
false value eva-debug?
true value fcode-debug?
defer fcode-rb@
defer fcode@

' c@ to fcode-rb@

create token-table 2000 cells allot    \ 1000h = 4096d

#include "core.fs"
#include "1275.fs"
#include "tokens.fs"
#include "locals.fs"

0 value buff
0 value buff-size

' read-fcode# to fcode@

( ---------------------------------------------------- )

: execute-rom-fcode ( addr len | false -- )
   reset-fcode-end
   ?dup IF
      diagnostic-mode? IF ." , executing ..." cr THEN
      dup >r r@ alloc-mem dup >r swap rmove
      r@ set-ip evaluate-fcode
      diagnostic-mode? IF ." Done." cr THEN
      r> r> free-mem
   THEN
;

: rom-code-ignored  ( image-addr name len -- image-addr )
   diagnostic-mode? IF
      type ."  code found in image " dup .  ." , ignoring ..." cr
   ELSE
      2drop
   THEN
;

: pci-find-rom ( baseaddr -- addr )
   dup IF
      dup rw@-le aa55 = IF
         diagnostic-mode? IF ." Device ROM header found at " dup . cr THEN
      ELSE
         drop 0
      THEN
   THEN
;

: pci-find-fcode ( baseaddr -- addr len | false )
   BEGIN
      1ff NOT and                       \ Image must start at 512 byte boundary
      pci-find-rom dup
   WHILE
      dup 18 + rw@-le +              ( pcir-addr )
      \ Check for PCIR magic ... since pcir-addr might not be
      \ 4-byte aligned, we've got to use two reads here:
      dup rw@-le 4350 ( 'PC' ) <>    ( pcir-addr hasPC? )
      over 2+ rw@-le 5249 ( 'IR' ) <> OR IF
         diagnostic-mode? IF
            ." Invalid PCI Data structure, ignoring ROM contents" cr
         THEN
         drop false EXIT
      THEN                           ( pcir-addr )
      dup 14 + rb@ CASE              \ Get image code type
         0 OF s" Intel x86 BIOS" rom-code-ignored ENDOF
         1 OF
            diagnostic-mode? IF
               ." Open Firmware FCode found in image at " dup . cr
            THEN
            dup 1ff NOT AND          \ Back to the ROM image header
            dup 2+ rw@-le +          \ Pointer to FCODE (PCI bus binding ch.9)
            swap 10 + rw@-le 200 *   \ Image length
            EXIT
         ENDOF
         2 OF s" HP PA RISC" rom-code-ignored ENDOF
         3 OF s" EFI" rom-code-ignored ENDOF
         dup OF s" Unknown type" rom-code-ignored ENDOF
      ENDCASE
      dup 15 + rb@ 80 and IF         \ End of last image?
         drop false EXIT
      THEN
      dup 10 + rw@-le  200 * +       \ Next image start
   REPEAT
;


\ Prepare and run a FCODE program from a PCI Option ROM.
: pci-execute-fcode  ( baseaddr -- )
   pci-find-fcode dup 0= IF
      2drop EXIT
   THEN                                 ( addr len )
   fc-set-pci-mmio-tokens               \ Prepare PCI access functions
   \ Now run the FCODE:
   ['] execute-rom-fcode CATCH IF
      cr ." FCODE failed!" cr
      2drop
   THEN
   fc-set-normal-mmio-tokens            \ Restore normal MMIO access functions
;
