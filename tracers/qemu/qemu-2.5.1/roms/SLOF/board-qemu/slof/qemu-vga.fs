\ *****************************************************************************
\ * Copyright (c) 2015 IBM Corporation
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

: map-in  " map-in" my-phandle parent $call-static ;
: map-out  " map-out" my-phandle parent $call-static ;

\ Determine base address
0 0  my-space h# 02000010 + 1  map-in VALUE fb-base
0 0  my-space h# 02000018 + 1 map-in VALUE reg-base

\ We support only one instance
false VALUE is-installed?

: vga-w! ( value port -- )
  3c0 - reg-base 400 + + rw!-le
;

: vga-w@ ( port -- value )
  3c0 - reg-base 400 + + rw@-le
;

: vga-b! ( value port -- )
  3c0 - reg-base 400 + + rb!
;

: vga-b@ ( port -- value )
  3c0 - reg-base 400 + + rb@
;

: vbe!	( value index -- )
  1 << reg-base 500 + + rw!-le
;

: vbe@	( index -- value )
  1 << reg-base 500 + + rw@-le
;

: color! ( r g b number -- )
   3c8 vga-b!
   rot 3c9 vga-b!
   swap 3c9 vga-b!
   3c9 vga-b!
;

: color@ ( number -- r g b )
   3c8 vga-b!
   3c9 vga-b@
   3c9 vga-b@
   3c9 vga-b@
;

: set-colors ( adr number #numbers -- )
   over 3c8 vga-b!
   swap DO
     rb@ 3c9 vga-b!
     rb@ 3c9 vga-b!
     rb@ 3c9 vga-b!
   LOOP
   3drop
;

: get-colors ( adr number #numbers -- )
   3drop
;

include graphics.fs

\ qemu fake VBE IO registers
0 CONSTANT VBE_DISPI_INDEX_ID
1 CONSTANT VBE_DISPI_INDEX_XRES
2 CONSTANT VBE_DISPI_INDEX_YRES
3 CONSTANT VBE_DISPI_INDEX_BPP
4 CONSTANT VBE_DISPI_INDEX_ENABLE
5 CONSTANT VBE_DISPI_INDEX_BANK
6 CONSTANT VBE_DISPI_INDEX_VIRT_WIDTH
7 CONSTANT VBE_DISPI_INDEX_VIRT_HEIGHT
8 CONSTANT VBE_DISPI_INDEX_X_OFFSET
9 CONSTANT VBE_DISPI_INDEX_Y_OFFSET
a CONSTANT VBE_DISPI_INDEX_NB

\ ENABLE register
00 CONSTANT VBE_DISPI_DISABLED
01 CONSTANT VBE_DISPI_ENABLED
02 CONSTANT VBE_DISPI_GETCAPS
20 CONSTANT VBE_DISPI_8BIT_DAC
40 CONSTANT VBE_DISPI_LFB_ENABLED
80 CONSTANT VBE_DISPI_NOCLEARMEM

: init-mode
  0 3c0 vga-b!
  VBE_DISPI_DISABLED VBE_DISPI_INDEX_ENABLE vbe!
  0 VBE_DISPI_INDEX_X_OFFSET vbe!
  0 VBE_DISPI_INDEX_Y_OFFSET vbe!
  disp-width VBE_DISPI_INDEX_XRES vbe!
  disp-height VBE_DISPI_INDEX_YRES vbe!
  disp-depth VBE_DISPI_INDEX_BPP vbe!
  VBE_DISPI_ENABLED VBE_DISPI_8BIT_DAC or VBE_DISPI_INDEX_ENABLE vbe!
  0 3c0 vga-b!
  20 3c0 vga-b!
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

: setup-properties
   \ Shouldn't this be done from open ?
   disp-width encode-int s" width" property
   disp-height encode-int s" height" property
   disp-width disp-depth 7 + 8 / * encode-int s" linebytes" property
   disp-depth encode-int s" depth" property
   s" ISO8859-1" encode-string s" character-set" property \ i hope this is ok...
   \ add "device_type" property
   s" display" device-type
   s" qemu,std-vga" encode-string s" compatible" property
   \ XXX We don't create an "address" property because Linux doesn't know what
   \ to do with it for >32-bit
;

\ words for installation/removal, needed by is-install/is-remove, see display.fs
: display-remove ( -- )
;

: slow-blink-screen ( -- )
    \ 32 msec delay for visually noticing the blink
    invert-screen 20 ms invert-screen
;

: display-install ( -- )
    is-installed? NOT IF
        ." Installing QEMU fb" cr
        fb-base to frame-buffer-adr
        clear-screen
        default-font
        set-font
        disp-width disp-height
        disp-width char-width / disp-height char-height /
        disp-depth 7 + 8 /                      ( width height #lines #cols depth )
        fb-install
	['] slow-blink-screen to blink-screen
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

pci-master-enable
pci-mem-enable
read-settings
init-mode
init-default-palette
setup-properties
' display-install is-install
' display-remove is-remove
set-alias
