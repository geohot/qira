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

: fc-abort ." FCode called abort: IP " get-ip . ( ." STACK: " .s ) depth dup 0< IF abort THEN . rdepth . cr  abort ;
: fc-0 ." 0(lit): STACK ( S: " depth . ." R: " rdepth . ." ): " depth 0> IF .s THEN 0 ;
: fc-1 ." 1(lit): STACK ( S: " depth . ." R: " rdepth . ." ): " depth 0> IF .s THEN 1 ;

: parse-1hex 1 hex-decode-unit ;

\ Adjust functions for accessing MMIO registers. According to IEEE 1275,
\ a bus device can substitute bus-specific implementations of r*@ and r*!
\ for use by its children, e.g. with respect to byte-order. Since PCI is
\ little endian by default, we've got to use the little endian accessor
\ functions for the PCI bus (some FCODE programs are expecting this behavior).
: fc-set-pci-mmio-tokens  ( -- )
   ['] rw@-le  0 232 set-token
   ['] rw!-le  0 233 set-token
   ['] rl@-le  0 234 set-token
   ['] rl!-le  0 235 set-token
   ['] rx@-le  0 22E set-token
   ['] rx!-le  0 22F set-token
;

\ Set normal MMIO access token behavior:
: fc-set-normal-mmio-tokens  ( -- )
   ['] rw@  0 232 set-token
   ['] rw!  0 233 set-token
   ['] rl@  0 234 set-token
   ['] rl!  0 235 set-token
   ['] rx@  0 22E set-token
   ['] rx!  0 22F set-token
;

: reset-token-table
  FFF 0 DO ['] ferror 0 i set-token LOOP
  ;

reset-token-table

' end0 0        00 set-token

\ 01...0F beginning code of 2-byte FCode sequences

' b(lit)      1 10 set-token

' b(')        1 11 set-token
' b(")        1 12 set-token
' bbranch     1 13 set-token
' b?branch    1 14 set-token
' b(loop)     1 15 set-token
' b(+loop)    1 16 set-token
' b(do)       1 17 set-token
' b(?do)      1 18 set-token
' i           0 19 set-token
' j           0 1A set-token
' b(leave)    1 1B set-token
' b(of)       1 1C set-token
' execute     0 1D set-token
' +           0 1E set-token
' -           0 1F set-token
' *           0 20 set-token
' /           0 21 set-token
' mod         0 22 set-token 
' and         0 23 set-token 
' or          0 24 set-token 
' xor         0 25 set-token 
' invert      0 26 set-token 
' lshift      0 27 set-token 
' rshift      0 28 set-token 
' >>a         0 29 set-token 
' /mod        0 2A set-token 
' u/mod       0 2B set-token
' negate      0 2C set-token 
' abs         0 2D set-token 
' min         0 2E set-token 
' max         0 2F set-token 
' >r          0 30 set-token 
' r>          0 31 set-token 
' r@          0 32 set-token 
' exit        0 33 set-token 
' 0=          0 34 set-token 
' 0<>         0 35 set-token 
' 0<          0 36 set-token 
' 0<=         0 37 set-token 
' 0>          0 38 set-token 
' 0>=         0 39 set-token 
' <           0 3A set-token
' >           0 3B set-token
' =           0 3C set-token
' <>          0 3D set-token
' u>          0 3E set-token
' u<=         0 3F set-token 
' u<          0 40 set-token 
' u>=         0 41 set-token 
' >=          0 42 set-token 
' <=          0 43 set-token 
' between     0 44 set-token 
' within      0 45 set-token 
' DROP        0 46 set-token
' DUP         0 47 set-token
' OVER        0 48 set-token
' SWAP        0 49 set-token
' ROT         0 4A set-token
' -ROT        0 4B set-token
' TUCK        0 4C set-token
' nip         0 4D set-token 
' pick        0 4E set-token 
' roll        0 4F set-token 
' ?dup        0 50 set-token 
' depth       0 51 set-token 
' 2drop       0 52 set-token 
' 2dup        0 53 set-token 
' 2over       0 54 set-token 
' 2swap       0 55 set-token 
' 2rot        0 56 set-token 
' 2/          0 57 set-token 
' u2/         0 58 set-token 
' 2*          0 59 set-token 
' /c          0 5A set-token
' /w          0 5B set-token 
' /l          0 5C set-token 
' /n          0 5D set-token 
' ca+         0 5E set-token 
' wa+         0 5F set-token 
' la+         0 60 set-token 
' na+         0 61 set-token 
' char+       0 62 set-token 
' wa1+        0 63 set-token 
' la1+        0 64 set-token 
' cell+       0 65 set-token 
' chars       0 66 set-token 
' /w*         0 67 set-token 
' /l*         0 68 set-token 
' cells       0 69 set-token 
' on          0 6A set-token 
' off         0 6B set-token 
' +!          0 6C set-token 
' @           0 6D set-token 
' fc-l@       0 6E set-token 
' fc-w@       0 6F set-token 
' fc-<w@      0 70 set-token 
' fc-c@       0 71 set-token 
' !           0 72 set-token 
' fc-l!       0 73 set-token 
' fc-w!       0 74 set-token 
' fc-c!       0 75 set-token 
' 2@          0 76 set-token 
' 2!          0 77 set-token 
' fc-move     0 78 set-token 
' fc-fill     0 79 set-token 
' comp        0 7A set-token 
' noop        0 7B set-token
' lwsplit     0 7C set-token 
' wljoin      0 7D set-token 
' lbsplit     0 7E set-token 
' bljoin      0 7F set-token 
' wbflip      0 80 set-token 
' upc         0 81 set-token 
' lcc         0 82 set-token 
' pack        0 83 set-token 
' count       0 84 set-token 
' body>       0 85 set-token 
' >body       0 86 set-token 
' fcode-revision 0 87 set-token 
' span        0 88 set-token 
' unloop      0 89 set-token 
' expect      0 8A set-token 
' alloc-mem   0 8B set-token
' free-mem    0 8C set-token
' key?        0 8D set-token 
' key         0 8E set-token 
' emit        0 8F set-token 
' type        0 90 set-token 
' (cr         0 91 set-token
' cr          0 92 set-token 
' #out        0 93 set-token
' #line       0 94 set-token
' hold        0 95 set-token 
' <#          0 96 set-token 
' u#>         0 97 set-token 
' sign        0 98 set-token 
' u#          0 99 set-token 
' u#s         0 9A set-token 
' u.          0 9B set-token 
' u.r         0 9C set-token 
' .           0 9D set-token 
' .r          0 9E set-token 
' .s          0 9F set-token 
' base        0 A0 set-token 
\ ' convert   0 A1 set-token            \ historical, not supported
' $number     0 A2 set-token 
' digit       0 A3 set-token 
' -1          0 A4 set-token
'  0          0 A5 set-token
'  1          0 A6 set-token
'  2          0 A7 set-token
'  3          0 A8 set-token
' bl          0 A9 set-token
' bs          0 AA set-token 
' bell        0 AB set-token 
' bounds      0 AC set-token 
' here        0 AD set-token 
' aligned     0 AE set-token 
' wbsplit     0 AF set-token 
' bwjoin      0 B0 set-token 
' b(<mark)    1 B1 set-token
' b(>resolve) 1 B2 set-token
\ ' set-token-table   0 B3 set-token    \ historical, not supported
\ ' set-table 0 B4 set-token            \ historical, not supported
' new-token   0 B5 set-token 
' named-token 0 B6 set-token
' b(:)        1 B7 set-token
' b(value)    1 B8 set-token 
' b(variable) 1 B9 set-token 
' b(constant) 1 BA set-token 
' b(create)   1 BB set-token 
' b(defer)    1 BC set-token 
' b(buffer:)  1 BD set-token 
' b(field)    1 BE set-token 
\ ' b(code)   0 BF set-token            \ historical, not supported
' fc-instance 1 C0 set-token 
\ ' ferror    0 C1 set-token            \ Reserved
' b(;)        1 C2 set-token
' b(to)       1 C3 set-token 
' b(case)     1 C4 set-token
' b(endcase)  1 C5 set-token
' b(endof)    1 C6 set-token
' #           0 C7 set-token
' #s          0 C8 set-token
' #>          0 C9 set-token
' external-token 0 CA set-token 
' $find       0 CB set-token
' offset16    0 CC set-token 
' evaluate    0 CD set-token
\             0  CE reserved
\             0  CF reserved
' c,          0  D0 set-token
' w,          0  D1 set-token
' l,          0  D2 set-token
' ,           0  D3 set-token
' um*         0  D4 set-token
' um/mod      0  D5 set-token
\             0  D6 reserved
\             0  D7 reserved
' d+          0  D8 set-token
' d-          0  D9 set-token
' get-token   0  DA set-token 
' set-token   0  DB set-token 
' state       0  DC set-token  \ possibly broken
' compile,    0  DD set-token
' behavior    0  DE set-token 

\ Tokens 0xDF to 0xEF are reserved

' start0            0  F0 set-token
' start1            0  F1 set-token
' start2            0  F2 set-token
' start4            0  F3 set-token

\ Tokens 0xF4 to 0xFB are reserved

' ferror            0  FC set-token
' version1          0  FD set-token

\ ' 4-byte-id       0  FE set-token    \ Historical, not supported
' end1              0  FF set-token

\                   0 100 set-token    \ reserved
' dma-alloc         0 101 set-token    \ Obsolete
' my-address        0 102 set-token 
' my-space          0 103 set-token
\ ' memmap          0 104 set-token    \ Obsolete
' free-virtual      0 105 set-token
\ ' >physical       0 106 set-token    \ Obsolete

\ Tokens 0x107 to 0x10e are reserved

' my-params         0 10f set-token    \ Obsolete
' property          0 110 set-token
' encode-int        0 111 set-token
' encode+           0 112 set-token
' encode-phys       0 113 set-token
' encode-string     0 114 set-token
' encode-bytes      0 115 set-token
' reg               0 116 set-token
' intr              0 117 set-token    \ Obsolete
' driver            0 118 set-token    \ Obsolete
' model             0 119 set-token
' device-type       0 11A set-token
' parse-2int        0 11B set-token
\ ' is-install      0 11C set-token    \ Will be set by framebuffer code
\ ' is-remove       0 11D set-token    \ Will be set by framebuffer code
\ ' is-selftest     0 11E set-token    \ Will be set by framebuffer code
' new-device        0 11F set-token
' diagnostic-mode?  0 120 set-token
' display-status    0 121 set-token    \ Maybe obsolete
' memory-test-suite 0 122 set-token
' group-code        0 123 set-token    \ Obsolete
' mask              0 124 set-token
' get-msecs         0 125 set-token
' ms                0 126 set-token
' finish-device     0 127 set-token
' decode-phys       0 128 set-token
\ ' push-package    0 129 set-token    \ TODO - from proposal 215
\ ' pop-package     0 12A set-token    \ TODO - from proposal 215
' interpose         0 12B set-token    \ Recommended practice: Interposition

\ Tokens 0x12C to 0x12F are reserved

' map-low           0 130 set-token
' sbus-intr>cpu     0 131 set-token    \ Obsolete

\ Tokens 0x132 to 0x14f are reserved

\ The following tokens will be set by the framebuffer code:
\ ' #lines            0 150 set-token
\ ' #columns          0 151 set-token
\ ' line#             0 152 set-token
\ ' column#           0 153 set-token
\ ' inverse?          0 154 set-token
\ ' inverse-screen?   0 155 set-token
\ ' frame-buffer-busy 0 156 set-token  \ Historical, not supported
\ ' draw-character    0 157 set-token
\ ' reset-screen      0 158 set-token
\ ' toggle-cursor     0 159 set-token
\ ' erase-screen      0 15A set-token
\ ' blink-screen      0 15B set-token
\ ' invert-screen     0 15C set-token
\ ' insert-characters 0 15D set-token
\ ' delete-characters 0 15E set-token
\ ' insert-lines      0 15F set-token
\ ' delete-lines      0 160 set-token
\ ' draw-logo         0 161 set-token
\ ' frame-buffer-adr  0 162 set-token
\ ' screen-height     0 163 set-token
\ ' screen-width      0 164 set-token
\ ' window-top        0 165 set-token
\ ' window-left       0 166 set-token
\ '                   0 167 set-token  \ Reserved
\ ' foreground-color  0 168 set-token  \ From 16-color recommended practice
\ ' background-color  0 169 set-token  \ From 16-color recommended practice
\ ' default-font      0 16A set-token
\ ' set-font          0 16B set-token
\ ' char-height       0 16C set-token
\ ' char-width        0 16D set-token
\ ' >font             0 16E set-token
\ ' fontbytes         0 16F set-token

\ Tokens 0x170 to 0x17C are obsolete fb1 functions
\ Tokens 0x17D to 0x17F are reserved

\ The following tokens will be set by the framebuffer code, too:
\ ' fb8-draw-character 0 180 set-token
\ ' fb8-reset-screen   0 181 set-token
\ ' fb8-toggle-cursor  0 182 set-token
\ ' fb8-erase-screen   0 183 set-token
\ ' fb8-blink-screen   0 184 set-token
\ ' fb8-invert-screen  0 185 set-token
\ ' fb8-insert-characters 0 186 set-token
\ ' fb8-delete-characters 0 187 set-token
\ ' fb8-insert-lines   0 188 set-token
\ ' fb8-delete-lines   0 189 set-token
\ ' fb8-draw-logo      0 18A set-token
\ ' fb8-install        0 18B set-token

\ Tokens 0x18C to 0x18F are reserved
\ Tokens 0x190 to 0x196 are obsolete VMEbus tokens
\ Tokens 0x197 to 0x19F are reserved

\ ' return-buffer   0 1A0 set-token       \ Historical, not supported
\ ' xmit-packet     0 1A1 set-token       \ Historical, not supported
\ ' poll-packet     0 1A2 set-token       \ Historical, not supported
\                   0 1A3 set-token       \ reserved
' mac-address       0 1A4 set-token

\ Tokens 0x1A5 to 0x200 are reserved

' device-name       0 201 set-token
' my-args           0 202 set-token
' my-self           0 203 set-token
' find-package      0 204 set-token
' open-package      0 205 set-token
' close-package     0 206 set-token
' find-method       0 207 set-token
' call-package      0 208 set-token
' $call-parent      0 209 set-token
' my-parent         0 20A set-token
' ihandle>phandle   0 20B set-token
\                   0 20C set-token       \ reserved
' my-unit           0 20D set-token
' $call-method      0 20E set-token
' $open-package     0 20F set-token
' processor-type    0 210 set-token       \ Obsolete
' firmware-version  0 211 set-token       \ Obsolete
' fcode-version     0 212 set-token       \ Obsolete
\ ' alarm           0 213 set-token       \ TODO
' (is-user-word)    0 214 set-token
' suspend-fcode     0 215 set-token
' fc-abort          0 216 set-token
' catch             0 217 set-token
' throw             0 218 set-token
\ ' user-abort      0 219 set-token       \ TODO
' get-my-property   0 21A set-token
' decode-int        0 21B set-token
' decode-string     0 21C set-token
' get-inherited-property 0 21D set-token  
' delete-property   0 21E set-token  
' get-package-property 0 21F set-token
' cpeek             0 220 set-token 
' wpeek             0 221 set-token 
' lpeek             0 222 set-token 
' cpoke             0 223 set-token 
' wpoke             0 224 set-token 
' lpoke             0 225 set-token 
' lwflip            0 226 set-token 
' lbflip            0 227 set-token 
' lbflips           0 228 set-token
\ ' adr-mask        0 229 set-token       \ Historical, not supported

\ Tokens 0x22A to 0x22F are reserved

' rb@               0 230 set-token
' rb!               0 231 set-token
fc-set-normal-mmio-tokens                 \ Set rw@, rw!, rl@, rl!, rx@ and rx!

' wbflips           0 236 set-token 
' lwflips           0 237 set-token 
\ ' probe           0 238 set-token       \ Obsolete
\ ' probe-virtual   0 239 set-token       \ Obsolete
\                   0 23A reserved
' child             0 23B set-token
' peer              0 23C set-token
' next-property     0 23D set-token
' byte-load         0 23E set-token
' set-args          0 23F set-token
' left-parse-string 0 240 set-token

\ 64-bit extension tokens:
' bxjoin            0 241 set-token
' fc-<l@            0 242 set-token
' lxjoin            0 243 set-token
' wxjoin            0 244 set-token
' x,                0 245 set-token
' fc-x@             0 246 set-token
' fc-x!             0 247 set-token
' /x                0 248 set-token
' /x*               0 249 set-token
' xa+               0 24A set-token
' xa1+              0 24B set-token
' xbflip            0 24C set-token
' xbflips           0 24D set-token
' xbsplit           0 24E set-token
' xlflip            0 24F set-token
' xlflips           0 250 set-token
' xlsplit           0 251 set-token
' xwflip            0 252 set-token
' xwflips           0 253 set-token
' xwsplit           0 254 set-token

\                    0 255 RESERVED FCODES 
\                    ...
\                    0 5FF RESERVED FCODES 

\                    0 600 VENDOR FCODES 
\                    ...
\                    0 7FF VENDOR FCODES 

\                    0 800 LOCAL FCODES 
\                    ...
\                    0 FFF LOCAL FCODES 

