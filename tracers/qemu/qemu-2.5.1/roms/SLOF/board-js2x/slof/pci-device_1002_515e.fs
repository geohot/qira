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

my-space pci-class-name type

my-space assign-all-device-bars
my-space pci-device-props
my-space pci-set-irq-line

7 4 config-w!

\ Special notice from ATI:
\ ATI TECHNOLOGIES INC. ("ATI") HAS NOT ASSISTED IN THE CREATION OF,
\ AND DOES NOT ENDORSE THE USE OF, THIS SOFTWARE.  ATI WILL NOT BE
\ RESPONSIBLE OR LIABLE FOR ANY ACTUAL OR ALLEGED DAMAGE OR LOSS
\ CAUSED BY OR IN CONNECTION WITH THE USE OF, OR RELIANCE ON,
\ THIS SOFTWARE.

\  Description: This FCODE driver initializes the RN50 (ES1000) ATI
\               adaptor.

-1 value mem-addr
-1 value regs-addr
false value is_installed

: reg-rl@ regs-addr + rl@-le ;
: reg-rl! regs-addr + rl!-le ;
: map-in   " map-in"   $call-parent ;
: map-out  " map-out"  $call-parent ;
: pc@ ( offset -- byte ) regs-addr + rb@ ;
: pc! ( byte offset -- ) regs-addr + rb! ;

0 value phys_low
0 value phys_mid
0 value phys_high
0 value phys_len

: MAP-CSR-BASE ( -- )
  " assigned-addresses" get-my-property 0= if
    begin dup 0> while  ( prop-addr len )
     \ Get the phys-hi mid low and the low order 32 bits of the length

      decode-phys to phys_high to phys_mid to phys_low decode-int drop decode-int to phys_len

      phys_high H# FF and  \ See which BAR this refers to
      case
        h# 10 of phys_low phys_mid phys_high h# 1000000  map-in to mem-addr  endof
        h# 18 of phys_low phys_mid phys_high    phys_len map-in to regs-addr endof
      endcase
    repeat
    ( prop-addr 0 ) 2drop
  then

  ;

: enable-card my-space 4 + dup config-b@ 3 or swap config-b! ;

: EARLY-MAP ( -- )

  " reg" get-my-property 0= if
    begin dup 0> while  ( prop-addr len )

   \ Get the phys-hi mid low and the low order 32 bits of the length

      decode-phys to phys_high to phys_mid to phys_low decode-int drop decode-int to phys_len

      phys_high H# FF and  \ See which BAR this refers to
      case
        h# 10 of phys_low phys_mid phys_high H# 1000000  map-in to mem-addr  endof
        h# 18 of phys_low phys_mid phys_high h#    1000  map-in to regs-addr endof
      endcase
    repeat
    ( prop-addr 0 ) 2drop
  then
  ;

: EARLY-UNMAP ( -- )

  mem-addr -1 <> if
    mem-addr h# 1000000 map-out
    -1 to mem-addr
  then

  regs-addr -1 <> if
    regs-addr h# 1000   map-out
    -1 to regs-addr
  then

  ;

CREATE INIT1_ARRAY
H# 0F8  ( CONFIG_MEMSIZE )  L,    H# 00000000 L, H# 01000000 L,
H# 1C0  ( MPP_TB_CONFIG )   L,    H# 00FFFFFF L, H# 07000000 L,
H# 030  ( BUS_CNTL      )   L,    H# 00000000 L, H# 5133A3B0 L,
H# 0EC  ( RBBM_CNTL     )   L,    H# 00000000 L, h# 00004443 L,
H# 1D0  ( DEBUG_CNTL    )   L,    H# FFFFFFFD L, H# 00000002 L,
H# 050  ( CRTC_GEN_CNTL )   L,    H# 00000000 L, H# 04000000 L,
H# 058  ( DAC_CNTL      )   L,    H# 00000000 L, H# FF604102 L,
H# 168  ( PAD_CTLR_STRENGTH ) L,  H# FFFEFFFF L, H# 00001200 L,
H# 178  ( MEM_REFRESH_CNTL  ) L,  H# 00000000 L, H# 88888888 L,
H# 17C  ( MEM_READ_CNTL )   L,    H# 00000000 L, H# B7C20000 L,
H# 188  ( MC_DEBUG      )   L,    H# FFFFFFFF L, H# 00000000 L,
H# D00  ( DISP_MISC_CNTL)   L,    H# 00FFFFFF L, H# 5B000000 L,
H# 88C  ( TV_DAC_CNTL   )   L,    H# F800FCEF L, H# 00490200 L,
H# D04  ( DAC_MACRO_CNTL)   L,    H# 00000000 L, H# 00000905 L,
H# 284  ( FP_GEN_CNTL   )   L,    H# FFFFFFFF L, H# 00000008 L,
H# 030  ( BUS_CNTL      )   L,    H# FFFFFFEF L, H# 00000000 L,

here  INIT1_ARRAY  - /L / CONSTANT INIT1_LENGTH


CREATE INIT2_ARRAY

H# 140  ( MEM_CNTL )           L, H#  00000000 L, H# 38001A01 L, 0 L,
H# 158  ( MEM_SDRAM_MODE_REG ) L, H#  E0000000 L, H# 08320032 L, 0 L,
H# 144  ( MEM_TIMING_CNTL    ) L, H#  00000000 L, H# 20123833 L, 0 L,
H# 14C  ( MC_AGP_LOCATION    ) L, H#  00000000 L, H# 000FFFF0 L, 0 L,
H# 148  ( MC_FB_LOCATION     ) L, H#  00000000 L, H# FFFF0000 L, 0 L,
H# 154  ( MEM_INIT_LAT_TIMER ) L, H#  00000000 L, H# 34444444 L, 0 L,
H# 18C  ( MC_CHP_IO_OE_CNTL  ) L, H#  00000000 L, H# 0A540002 L, 0 L,
H# 910  ( FCP_CNTL           ) L, H#  00000000 L, H# 00000004 L, 0 L,
H# 010  ( BIOS_0_SCRATCH     ) L, H#  FFFFFFFB L, H# 00000004 L, 0 L,
H# D64  ( DISP_OUTPUT_CNTL   ) L, H#  FFFFFBFF L, H# 00000000 L, 0 L,
H# 2A8  ( TMDS_PLL_CNTL      ) L, H#  00000000 L, H# 00000A1B L, 0 L,
H# 800  ( TV_MASTER_CNTL     ) L, H#  BFFFFFFF L, H# 40000000 L, 0 L,
H# D10  ( DISP_TEST_DBUG_CTL ) L, H#  EFFFFFFF L, H# 10000000 L, 0 L,
H# 4DC  ( OV0_FLAG_CNTRL     ) L, H#  FFFFFEFF L, H# 00000100 L, 0 L,
H# 034  ( BUS_CNTL1          ) L, H#  73FFFFFF L, H# 84000000 L, 0 L,
H# 174  ( AGP_CNTL           ) L, H#  FFEFFF00 L, H# 001E0000 L, 0 L,
H# 18C  ( MC_CHP_IO_OE_CNTL  ) L, H#  FFFFFFF9 L, H# 00000006 L, h# 000A L,
H# 18C  ( MC_CHP_IO_OE_CNTL  ) L, H#  FFFFFFFB L, H# 00000000 L, H# 000A L,
H# 18C  ( MC_CHP_IO_OE_CNTL  ) L, H#  FFFFFFFD L, H# 00000000 L, 0 L,

here  INIT2_ARRAY  - /L / CONSTANT INIT2_LENGTH

CREATE PLLINIT_ARRAY

H# 0D   L, H# FFFFFFFF L, H# FFFF8000 L, 0 L,
H# 12   L, H# FFFFFFFF L, H# 00350000 L, 0 L,
H# 08   L, H# FFFFFFFF L, H# 00000000 L, 0 L,
H# 2D   L, H# FFFFFFFF L, H# 00000000 L, 0 L,
H# 1F   L, H# FFFFFFFF L, H# 0000000A L, 5 L,
H# 03   L, H# FFFFFFFF L, H# 0000003C L, 0 L,
H# 0A   L, H# FFFFFFFF L, H# 00252504 L, 0 L,
H# 25   L, H# FFFFFFFF L, H# 00000005 L, 0 L,
H# 0E   L, H# FFFFFFFF L, H# 04756400 L, 0 L,
H# 0C   L, H# FFFFFFFF L, H# 04006401 L, 0 L,
H# 02   L, H# FFFFFFFF L, H# 0000A703 L, 0 L,
H# 0F   L, H# FFFFFFFF L, H# 0000051C L, 0 L,
H# 10   L, H# FFFFFFFF L, H# 04000400 L, 5 L,
H# 0E   L, H# FFFFFFFD L, H# 00000000 L, 5 L,
H# 0E   L, H# FFFFFFFE L, H# 00000000 L, 5 L,
H# 12   L, H# FFFFFFFF L, H# 00350012 L, 5 L,
H# 0F   L, H# FFFFFFFE L, H# 00000000 L, 6 L,
H# 10   L, H# FFFFFFFE L, H# 00000000 L, 5 L,
H# 10   L, H# FFFEFFFF L, H# 00000000 L, 6 L,
H# 0F   L, H# FFFFFFFD L, H# 00000000 L, 5 L,
H# 10   L, H# FFFFFFFD L, H# 00000000 L, 5 L,
H# 10   L, H# FFFDFFFF L, H# 00000000 L, d# 10 L,
H# 0C   L, H# FFFFFFFE L, H# 00000000 L, 6 L,
H# 0C   L, H# FFFFFFFD L, H# 00000000 L, 5 L,
h# 0D   L, H# FFFFFFFF L, H# FFFF8007 L, 5 L,
H# 08   L, H# FFFFFF3C L, H# 00000000 L, 0 L,
H# 02   L, H# FFFFFFFF L, H# 00000003 L, 0 L,
H# 04   L, H# FFFFFFFF L, H# 000381C0 L, 0 L,
H# 05   L, H# FFFFFFFF L, H# 000381F7 L, 0 L,
H# 06   L, H# FFFFFFFF L, H# 000381C0 L, 0 L,
H# 07   L, H# FFFFFFFF L, H# 000381F7 L, 0 L,
H# 02   L, H# FFFFFFFD L, H# 00000000 L, 6 L,
H# 02   L, H# FFFFFFFE L, H# 00000000 L, 5 L,
h# 08   L, H# FFFFFF3C L, H# 00000003 L, 5 L,
H# 0B   L, H# FFFFFFFF L, H# 78000800 L, 0 L,
H# 0B   L, H# FFFFFFFF L, H# 00004000 L, 0 L,
h# 01   L, h# FFFFFFFF L, H# 00000010 L, 0 L,

here  PLLINIT_ARRAY  - /L / CONSTANT PLLINIT_LENGTH

CREATE MEMINIT_ARRAY
h# 6FFF0000  L, H# 00004000 L, H# 6FFF0000 L, H# 80004000 L,
h# 6FFF0000  L, H# 00000132 L, H# 6FFF0000 L, H# 80000132 L,
h# 6FFF0000  L, H# 00000032 L, H# 6FFF0000 L, H# 80000032 L,
h# 6FFF0000  L, H# 10000032 L,
here MEMINIT_ARRAY - /L / CONSTANT MEMINIT_LENGTH
: L@+ ( addr -- value addr' )

dup l@ swap la1+
;

0 VALUE _len

: ENCODE-ARRAY  ( array len -- )
   dup to _len 0  do  l@+ swap encode-int rot  loop
   drop _len 1 - 0  ?do  encode+  loop
;

: andorset  ( reg and or -- )
   2 pick dup reg-rl@
   3 pick AND 2 pick OR swap reg-rl! 3drop
;

: INIT1
H# 0F8  ( CONFIG_MEMSIZE )      H# 00000000  H# 01000000 andorset \ Set 16Mb memory size
H# 1C0  ( MPP_TB_CONFIG )       H# 00FFFFFF  H# 07000000 andorset
H# 030  ( BUS_CNTL      )       H# 00000000  H# 5133A3B0 andorset
H# 0EC  ( RBBM_CNTL     )       H# 00000000  h# 00004443 andorset
H# 1D0  ( DEBUG_CNTL    )       H# FFFFFFFD  H# 00000002 andorset
H# 050  ( CRTC_GEN_CNTL )       H# 00000000  H# 04000000 andorset
H# 058  ( DAC_CNTL      )       H# 00000000  H# FF604102 andorset
H# 168  ( PAD_CTLR_STRENGTH )   H# FFFEFFFF  H# 00001200 andorset
H# 178  ( MEM_REFRESH_CNTL  )   H# 00000000  H# 88888888 andorset
H# 17C  ( MEM_READ_CNTL )       H# 00000000  H# B7C20000 andorset
H# 188  ( MC_DEBUG      )       H# FFFFFFFF  H# 00000000 andorset
H# D00  ( DISP_MISC_CNTL)       H# 00FFFFFF  H# 5B000000 andorset
H# 88C  ( TV_DAC_CNTL   )       H# F800FCEF  H# 00490200 andorset
H# D04  ( DAC_MACRO_CNTL)       H# 00000000  H# 00000905 andorset
H# 284  ( FP_GEN_CNTL   )       H# FFFFFFFF  H# 00000008 andorset
H# 030  ( BUS_CNTL      )       H# FFFFFFEF  H# 00000000 andorset
;


: INIT2
H# 140  ( MEM_CNTL )            H#  00000000  H# 38001A01 andorset
H# 158  ( MEM_SDRAM_MODE_REG )  H#  E0000000  H# 08320032 andorset
H# 144  ( MEM_TIMING_CNTL    )  H#  00000000  H# 20123833 andorset
H# 14C  ( MC_AGP_LOCATION    )  H#  00000000  H# 000FFFF0 andorset
H# 148  ( MC_FB_LOCATION     )  H#  00000000  H# FFFF0000 andorset
H# 154  ( MEM_INIT_LAT_TIMER )  H#  00000000  H# 34444444 andorset
H# 18C  ( MC_CHP_IO_OE_CNTL  )  H#  00000000  H# 0A540002 andorset
H# 910  ( FCP_CNTL           )  H#  00000000  H# 00000004 andorset
H# 010  ( BIOS_0_SCRATCH     )  H#  FFFFFFFB  H# 00000004 andorset
H# D64  ( DISP_OUTPUT_CNTL   )  H#  FFFFFBFF  H# 00000000 andorset
H# 2A8  ( TMDS_PLL_CNTL      )  H#  00000000  H# 00000A1B andorset
H# 800  ( TV_MASTER_CNTL     )  H#  BFFFFFFF  H# 40000000 andorset
H# D10  ( DISP_TEST_DEBUG_CTL ) H#  EFFFFFFF  H# 10000000 andorset
H# 4DC  ( OV0_FLAG_CNTRL     )  H#  FFFFFEFF  H# 00000100 andorset
H# 034  ( BUS_CNTL1          )  H#  73FFFFFF  H# 84000000 andorset
H# 174  ( AGP_CNTL           )  H#  FFEFFF00  H# 001E0000 andorset
H# 18C  ( MC_CHP_IO_OE_CNTL  )  H#  FFFFFFF9  H# 00000006 andorset h# 000A ms
H# 18C  ( MC_CHP_IO_OE_CNTL  )  H#  FFFFFFFB  H# 00000000 andorset H# 000A ms
H# 18C  ( MC_CHP_IO_OE_CNTL  )  H#  FFFFFFFD  H# 00000000 andorset
;

: CLK-CNTL-INDEX! 8 ( CLK_CNTL_INDEX ) reg-rl! ;

: CLK-CNTL-INDEX@ 8 ( CLK_CNTL_INDEX ) reg-rl@ ;

: PLLWRITEON  clk-cntl-index@ H# 80 ( PLL_WR_ENABLE ) or clk-cntl-index! ;

: PLLWRITEOFF clk-cntl-index@ H# 80 ( PLL_WR_ENABLE ) not and clk-cntl-index! ; \ Remove PLL_WR_ENABLE

: CLKDATA! h# 0c ( CLK_CNTL_DATA ) reg-rl! ;

: CLKDATA@ h# 0c ( CLK_CNTL_DATA ) reg-rl@ ;

: PLLINDEXSET clk-cntl-index@ h# FFFFFFC0 and or clk-cntl-index! ;

: PLLSET swap pllindexset clkdata! ;

: pllandorset  ( index and or -- )
   2 pick pllindexset clkdata@
   2 pick AND over OR clkdata! 3drop
;

: PLLINIT
pllwriteon
H# 0D   H# FFFF8000 pllset
H# 12   H# 00350000 pllset
H# 08   H# 00000000 pllset
H# 2D   H# 00000000 pllset
H# 1F   H# 0000000A pllset 5 ms

H# 03   H# 0000003C pllset
H# 0A   H# 00252504 pllset
H# 25   H# 00000005 pllset
H# 0E   H# 04756400 pllset
H# 0C   H# 04006401 pllset
H# 02   H# 0000A703 pllset
H# 0F   H# 0000051C pllset
H# 10   H# 04000400 pllset 5 ms

H# 0E   H# FFFFFFFD 00 pllandorset 5 ms
H# 0E   H# FFFFFFFE 00 pllandorset 5 ms
H# 12   H# 00350012 pllset 5 ms
H# 0F   H# FFFFFFFE 00 pllandorset 6 ms
H# 10   H# FFFFFFFE 00 pllandorset 5 ms
H# 10   H# FFFEFFFF 00 pllandorset 6 ms
H# 0F   H# FFFFFFFD 00 pllandorset 5 ms
H# 10   H# FFFFFFFD 00 pllandorset 5 ms
H# 10   H# FFFDFFFF 00 pllandorset d# 10 ms
H# 0C   H# FFFFFFFE 00 pllandorset 6 ms
H# 0C   H# FFFFFFFD 00 pllandorset 5 ms
h# 0D   h# FFFF8007      pllset 5 ms
H# 08   H# FFFFFF3C 00   pllandorset
H# 02   h# FFFFFFFF 03   pllandorset
H# 04   H# 000381C0      pllset
H# 05   H# 000381F7      pllset
H# 06   H# 000381C0      pllset
H# 07   H# 000381F7      pllset
H# 02   H# FFFFFFFD 00   pllandorset 6 ms
H# 02   h# FFFFFFFE 00   pllandorset 5 ms
h# 08   H# FFFFFF3C 03   pllandorset 5 ms
H# 0B   h# 78000800      pllset
H# 0B   H# FFFFFFFF h# 4000 pllandorset
h# 01   h# FFFFFFFF h# 0010 pllandorset

pllwriteoff
;

: DYNCKE
pllwriteon
H# 14   H# FFFF3FFF H# 30 pllandorset
H# 14   H# FF1FFFFF H# 00 pllandorset
H# 01   h# FFFFFFFF h# 80 pllandorset
H# 0D   H# 00000007       pllset 5 ms
h# 2D   H# 0000F8C0       pllset
h# 08   H# FFFFFFFF h# C0 pllandorset 5 ms
pllwriteoff
;

: MEM-MODE@
    h# 158 ( MEM_SDRAM_MODE_REG ) reg-rl@ ;

: MEM-MODE!
    h# 158 ( MEM_SDRAM_MODE_REG ) reg-rl! ;

: MEM-STATUS@
    H# 150 reg-rl@ ;

: WAIT-MEM-CMPLT
    h# 8000 0 do mem-status@ 3 and 3 = if leave then loop ;

: INITMEM

  mem-mode@ h# 6FFF0000 and h# 4000     or mem-mode!
  mem-mode@ h# 6FFF0000 and h# 80004000 or mem-mode!
  wait-mem-cmplt
  mem-mode@ h# 6FFF0000 and h# 0132     or mem-mode!
  mem-mode@ h# 6FFF0000 and h# 80000132 or mem-mode!
  wait-mem-cmplt
  mem-mode@ h# 6FFF0000 and h# 0032     or mem-mode!
  mem-mode@ h# 6FFF0000 and h# 80000032 or mem-mode!
  wait-mem-cmplt
  mem-mode@ h# 6FFF0000 and h# 10000032 or mem-mode!
;



: CLR-REG ( reg -- )
  0 swap  reg-rl!

;
: SET-PALETTE  ( -- )
  h# 0 h# b0 pc!                \ Reset PALETTE_INDEX

  d# 16 0 do
    H# 000000 h# B4 reg-rl!     \ Write the PALETTE_DATA ( Auto increments)
    H# aa0000 H# B4 reg-rl!
    H# 00aa00 H# B4 reg-rl!
    H# aa5500 H# B4 reg-rl!
    H# 0000aa H# B4 reg-rl!
    H# aa00aa H# B4 reg-rl!
    H# 00aaaa H# B4 reg-rl!
    H# aaaaaa H# B4 reg-rl!
    H# 555555 H# B4 reg-rl!
    H# ff5555 H# B4 reg-rl!
    H# 55ff55 H# B4 reg-rl!
    H# ffff55 H# B4 reg-rl!
    H# 5555ff H# B4 reg-rl!
    H# ff55ff H# B4 reg-rl!
    H# 55ffff H# B4 reg-rl!
    H# ffffff H# B4 reg-rl!
  loop

 ;

0 VALUE _addr
0 VALUE _color

: DO-COLOR  ( color-addr addr color -- )
   to _color to _addr 0 to _color
   3 0  do  _addr i + c@ 2 i - 8 * << _color + to _color  loop
   _color h# B4 reg-rl!
;

: SET-COLORS ( addr index #indices -- )

  swap h# B0 pc!
  ( addr #indices ) 0 ?do dup ( index ) i 3 * + DO-COLOR loop
  ( addr ) drop ;

: init-card

  h# FF h# 58 3 + pc!   \
  h# 59 pc@ h# FE and  h# 59 pc!   \
  h# 50 reg-rl@ H# FEFFFFFF AND h# 02000200 or  \ Clear 24 set 25 and 8-11 to 2
  h# 50 reg-rl!
  h# 4F0063  h# 200 reg-rl!
  H# 8C02A2  h# 204 reg-rl!
  H# 1Df020C h# 208 reg-rl!
  h# 8201EA  h# 20C reg-rl!
  h# 50 reg-rl@ H# F8FFFFFF AND h# 03000000 or h# 50 reg-rl!
  h# 50 h# 22C reg-rl!
  set-palette

  \ at this point for some reason mem-addr does not point
  \ to the right address and therefore the following command
  \ which should probably clean the frame buffer just
  \ overwrites everything starting from 0 including the
  \ exception vectors

  \ mem-addr h# F0000 0 fill
 ;

: DO-INIT
  early-map
  enable-card
  init1
  pllinit
  init2
  initmem
  init-card
  h# 8020 h# 54 reg-rl!
  early-unmap
;

d# 640 constant /scanline
d# 480 constant #scanlines
/scanline #scanlines * constant /fb

" okay" encode-string " status" property

: display-install ( -- )
  is_installed not if
    map-csr-base
    enable-card
    mem-addr to frame-buffer-adr
    h# 8020 h# 54 reg-rl!
    default-font set-font
    /scanline #scanlines  d# 100 d# 40 fb8-install
    true to is_installed
  then
;

: display-remove  ( -- )  ;

do-init                                                 \ Set up the card
\ clear at least 640x480
10 config-l@ 8 - F0000 0 rfill
init1_array init1_length encode-array " ibm,init1" property
init2_array init2_length encode-array " ibm,init2" property
pllinit_array pllinit_length   encode-array " ibm,pllinit" property
meminit_array meminit_length   encode-array " ibm,meminit" property
0 0 encode-bytes " iso6429-1983-colors" property
s" display" device-type
/scanline  encode-int " width" property
 #scanlines encode-int " height" property
8 encode-int " depth" property
/scanline  encode-int " linebytes" property

' display-install is-install
' display-remove is-remove

: fill-rectangle ( index x y w h -- )
  2swap -rot /scanline * + frame-buffer-adr + ( index w h fbadr )
  swap 0 ?do ( index w fbadr )
    3dup swap rot fill ( index w fbadr )
    /scanline + ( index w fbadr' )
  loop
  3drop
;
: draw-rectangle ( addr x y w h -- )
 2swap -rot /scanline * + frame-buffer-adr + ( addr w h fbadr )
 swap 0 ?do ( addr w fbadr )
   3dup swap move ( addr w fbadr )
    >r tuck + swap r> ( addr' w fbadr )
    /scanline + ( addr' w fbadr' )
  loop
  3drop
 ;
 : read-rectangle ( addr x y w h -- )
  2swap -rot /scanline * + frame-buffer-adr + ( addr w h fbadr )
  swap 0 ?do ( addr w fbadr )
    3dup -rot move ( addr w fbadr )
    >r tuck + swap r> ( addr' w fbadr )
    /scanline + ( addr' w fbadr' )
  loop
  3drop
 ;

: dimensions  ( -- width height )  /scanline #scanlines  ;

."  ( rn50 )" cr
