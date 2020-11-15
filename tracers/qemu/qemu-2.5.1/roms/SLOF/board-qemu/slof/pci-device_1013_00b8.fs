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

my-space pci-device-generic-setup

\ Defaults, overriden from qemu
d# 800 VALUE disp-width
d# 600 VALUE disp-height
d#   8 VALUE disp-depth

\ Determine base address
10 config-l@ translate-my-address f not AND  VALUE fb-base

\ Fixed up later
-1 VALUE io-base

\ We support only one instance
false VALUE is-installed?

: vga-io-xlate ( port -- addr )
  io-base -1 = IF
    dup translate-my-address fff not and to io-base
  THEN
  io-base +
;

: vga-w! ( value port -- )
  vga-io-xlate rw!-le
;

: vga-w@ ( port -- value )
  vga-io-xlate rw@-le
;

: vga-b! ( value port -- )
  vga-io-xlate rb!
;

: vga-b@ ( port -- value )
  vga-io-xlate rb@
;

: vga-crt@ ( index -- value )
  3d4 vga-b!
  3d5 vga-b@
;

: vga-crt! ( value index -- )
  3d4 vga-b!
  3d5 vga-b!
;

: vga-seq@ ( index -- value )
  3c4 vga-b!
  3c5 vga-b@
;

: vga-seq! ( value index -- )
  3c4 vga-b!
  3c5 vga-b!
;

: vga-att@ ( index -- value )
  3c0 vga-b!
  3c1 vga-b@
;

: vga-att! ( value index -- )
  3c0 vga-b!
  3c0 vga-b!
;

: vga-gfx@ ( index -- value )
  3ce vga-b!
  3cf vga-b@
;

: vga-gfx! ( value index -- )
  3ce vga-b!
  3cf vga-b!
;

: color! ( r g b number -- ) 
   3c8 vga-b!
   rot 2 >> 3c9 vga-b!
   swap 2 >> 3c9 vga-b!
   2 >> 3c9 vga-b!
;

: color@ ( number -- r g b ) 
   3c8 vga-b!
   3c9 vga-b@ 2 <<
   3c9 vga-b@ 2 <<
   3c9 vga-b@ 2 <<
;

: set-colors ( adr number #numbers -- )
   over 3c8 vga-b!
   swap DO
     rb@ 2 >> 3c9 vga-b!
     rb@ 2 >> 3c9 vga-b!
     rb@ 2 >> 3c9 vga-b!
   LOOP
   3drop
;

: get-colors ( adr number #numbers -- )
   3drop
;

include graphics.fs

: init-mode
  3da vga-b@ drop \ reset flip flop
  0f 3c2 vga-b!   \ color mode, ram enable, ...
  12 06 vga-seq!  \ unlock extensions
  05 06 vga-gfx!  \ graphic mode  
  \ set bit depth. Note: we should set the hidden
  \ dac register to differenciate 15 and 16bpp, but
  \ it's annoying and in practice we don't care as
  \ we are only displaying in black & white atm
  disp-depth CASE \ set depth
     8 OF 01 07 vga-seq! ENDOF
     f OF 07 07 vga-seq! ENDOF
    10 OF 07 07 vga-seq! ENDOF
    20 OF 09 07 vga-seq! ENDOF
  ENDCASE
  ff 02 vga-seq!  \ enable plane write
  0a 04 vga-seq!  \ memory mode
  03 17 vga-crt!  \ disable display
  \ calculate line offset & split
  disp-width disp-depth 7 + 8 / * 3 >>
  dup ff and 13 vga-crt!  \ bottom bits
  4 >> 10 and 1b vga-crt! \ top bit
  disp-width 3 >> 1 -                  01 vga-crt! \ H_DISP
  disp-height 1 - ff and               12 vga-crt! \ V_DISP
  disp-height 1 - 7 >> 2 and
  disp-height 1 - 3 >> 40 and
  or 10 or                             07 vga-crt! \ OFLOW
  ff 18 vga-crt! \ LINE_COMPARE
  40 09 vga-crt! \ MAX_SCAN
  08 04 vga-crt! \ SYNC_START
  0f 02 vga-crt! \ BLANK_START
  00 0c vga-crt!
  00 0d vga-crt!
  40 05 vga-gfx! \ gfx mode
  83 17 vga-crt! \ enable display
  33 3c0 vga-b!  \ gfx in ar index
  00 3c0 vga-b!
  01 01 vga-seq! \ enable seq
;

: clear-screen
  fb-base disp-width disp-height disp-depth 7 + 8 / * * 0 rfill
;

: read-settings
  s" qemu,graphic-width" get-chosen IF
     decode-int to disp-width 2drop
  THEN
  s" qemu,graphic-height" get-chosen IF
     decode-int to disp-height 2drop
  THEN
  s" qemu,graphic-depth" get-chosen IF
     decode-int nip nip     
       dup 8 =
       over f = or
       over 10 = or
       over 20 = or IF
         to disp-depth
       ELSE
         ." Unsupported bit depth, using 8bpp " drop cr
       THEN
  THEN
;

: add-legacy-reg
  \ add legacy I/O Ports / Memory regions to assigned-addresses
  \ see PCI Bus Binding Revision 2.1 Section 7.
  s" reg" get-node get-property IF
    \ "reg" does not exist, create new
    encode-start
  ELSE
    \ "reg" does exist, copy it 
    encode-bytes
  THEN
  \ I/O Range 0x1ce-0x1d2
  my-space a1000000 or encode-int+ \ non-relocatable, aliased I/O space
  1ce encode-64+ 4 encode-64+ \ addr size
  \ I/O Range 0x3B0-0x3BB
  my-space a1000000 or encode-int+ \ non-relocatable, aliased I/O space
  3b0 encode-64+ c encode-64+ \ addr size
  \ I/O Range 0x3C0-0x3DF
  my-space a1000000 or encode-int+ \ non-relocatable, aliased I/O space
  3c0 encode-64+ 20 encode-64+ \ addr size
  \ Memory Range 0xA0000-0xBFFFF
  my-space a2000000 or encode-int+ \ non-relocatable, <1MB Memory space
  a0000 encode-64+ 20000 encode-64+ \ addr size
  s" reg" property \ store "reg" property
;

: setup-properties
   \ Shouldn't this be done from open ?
   disp-width encode-int s" width" property
   disp-height encode-int s" height" property
   disp-width disp-depth 7 + 8 / * encode-int s" linebytes" property
   disp-depth encode-int s" depth" property
   s" ISO8859-1" encode-string s" character-set" property \ i hope this is ok...
   \ add "device_type" property
   s" display" device-type
   \ XXX We don't create an "address" property because Linux doesn't know what
   \ to do with it for >32-bit
;

\ words for installation/removal, needed by is-install/is-remove, see display.fs
: display-remove ( -- ) 
;

: display-install ( -- )
    is-installed? NOT IF
        ." Installing QEMU fb" cr
        fb-base to frame-buffer-adr
        default-font 
        set-font
        disp-width disp-height
        disp-width char-width / disp-height char-height /
        disp-depth 7 + 8 /                      ( width height #lines #cols depth )
        fb-install
        true to is-installed?
    THEN
;

: set-alias
    s" screen" find-alias 0= IF
      \ no previous screen alias defined, define it...
      s" screen" get-node node>path set-alias
    ELSE
       drop
    THEN 
;


." cirrus vga" cr

pci-master-enable
pci-mem-enable
pci-io-enable
add-legacy-reg
read-settings
init-mode
clear-screen
init-default-palette
setup-properties
' display-install is-install
' display-remove is-remove
set-alias
