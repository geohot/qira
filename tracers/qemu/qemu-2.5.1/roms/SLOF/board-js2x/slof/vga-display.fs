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

\ included by pci-class_03.fs

( str len display_num ) \ name prefix

false value is-installed?
value display_num ( str len )

s" ,Display-" $cat 41 display_num + char-cat \ add ", Display-A" or "-B" to name ( str len )
encode-string s" name" property \ store as name property

s" display" device-type

\ screen-info is set by pci-class_03.fs contains output of get_vbe_info bios-snk call
CASE screen-info c@ \ ( display-type )
   0 OF s" NONE" ENDOF \ No display
   1 OF s" Analog" ENDOF
   2 OF s" Digital" ENDOF
ENDCASE
encode-string s" display-type" property 

screen-info 8 + l@ value mem-adr
screen-info 1 + w@ value width
screen-info 3 + w@ value height

screen-info c@ IF
   \ if screen-info is not 0, we have some screen attached, add needed properties...
   width encode-int s" width" property
   height encode-int s" height" property
   screen-info 5 + w@ encode-int s" linebytes" property
   screen-info 7 + c@ encode-int s" depth" property
   mem-adr encode-int s" address" property
   \ the EDID property breaks the boot... so i leave it out for now, 
   \ maybe encode-bytes does s.th. wrong???
   \ screen-info c + 80 encode-bytes s" EDID" property
   s" ISO8859-1" encode-string s" character-set" property \ i hope this is ok...
THEN

\ words for installation/removal, needed by is-install/is-remove, see display.fs
: display-remove ( -- ) 
;
: display-install ( -- ) 
   is-installed? NOT IF 
      mem-adr to frame-buffer-adr 
      default-font 
      set-font
      width height width char-width / height char-height / ( width height #lines #cols )
      fb8-install 
      true to is-installed?
   THEN
;

: color! ( r g b number -- ) 
   \ 3c8 is RAMDAC write mode select palette entry register
   \ 3c9 is RAMDAC write mode write palette entry register ( 3 consecutive writes set new entry )
   vga-device-node? 3c8 translate-address ( r g b number address ) 
   swap 1 pick ( r g b address number address )
   rb! \ write palette entry number ( r g b address )
   1 + \ select next register (3c9)
   dup 4 pick swap rb! \ write red ( r g b address )
   dup 3 pick swap rb! \ write green ( r g b address )
   dup 2 pick swap rb! \ write blue ( r g b address )
   4drop
;

: color@ ( number -- r g b ) 
   \ 3c7 is RAMDAC read mode select palette entry register
   \ 3c9 is RAMDAC read mode read palette entry register ( 3 consecutive reads read entry )
   vga-device-node? 3c7 translate-address ( number address ) 
   swap 1 pick ( address number address )
   rb! \ write palette entry number ( address )
   2 + >r \ select next register (3c9) ( R: address )
   r@ rb@ \ read red ( r R: address )
   r@ rb@ \ read green ( r g R: address )
   r@ rb@ \ write blue ( r g b R: address )
   r> drop ( r g b )
;

: set-colors ( adr number #numbers -- )
   \ 3c8 is RAMDAC write mode select palette entry register
   \ 3c9 is RAMDAC write mode write palette entry register ( 3 consecutive writes set new entry )
   \ since after writing 3 entries, the palette entry is automagically incremented, 
   \ we can just continue writing...
   vga-device-node? 3c8 translate-address ( adr number #numbers ) 
   dup 3 pick swap ( adr number #numbers address number address )
   rb! \ write palette entry number ( adr number #numbers address )
   1 + \ select next register (3c9)  
   -rot swap drop ( adr address #numbers )
   -rot swap rot  ( address adr #numbers )
   0 ?DO
      ( address adr )
      dup rb@ \ read red value from adr ( address adr r )
      2 pick rb! \ write to register ( address adr )
      1 + \ next adr 
      dup rb@ \ read green value from adr ( address adr g )
      2 pick rb! \ write to register ( address adr )
      1 + \ next adr 
      dup rb@ \ read blue value from adr ( address adr r )
      2 pick rb! \ write to register ( address adr )
      1 + \ next adr 
   LOOP
   2drop
;

: get-colors ( adr number #numbers -- )
   \ 3c7 is RAMDAC read mode select palette entry register
   \ 3c9 is RAMDAC read mode read palette entry register ( 3 consecutive reads get entry )
   \ since after reading 3 entries, the palette entry is automagically incremented, 
   \ we can just continue reading...
   vga-device-node? 3c7 translate-address ( adr number #numbers ) 
   dup 3 pick swap ( adr number #numbers address number address )
   rb! \ write palette entry number ( adr number #numbers address )
   2 + \ select next register (3c9)  
   -rot swap drop ( adr address #numbers )
   -rot swap rot  ( address adr #numbers )
   0 ?DO
      ( address adr )
      1 pick rb@ \ read red value from register ( address adr r )
      1 pick rb! \ write to adr ( address adr )
      1 + \ next adr 
      1 pick rb@ \ read green value from register ( address adr g )
      1 pick rb! \ write to adr ( address adr )
      1 + \ next adr 
      1 pick rb@ \ read blue value from register ( address adr b )
      1 pick rb! \ write to adr ( address adr )
      1 + \ next adr 
   LOOP
   2drop
;

include graphics.fs

\ clear screen 
mem-adr width height * 0 rfill

\ call is-install and is-remove
' display-install is-install

' display-remove is-remove

s" screen" find-alias 0= IF
   \ no previous screen alias defined, define it...
   s" screen" get-node node>path set-alias
ELSE
   drop
THEN 
