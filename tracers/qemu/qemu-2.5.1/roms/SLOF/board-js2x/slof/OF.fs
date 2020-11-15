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

\ The master file.  Everything else is included into here.

hex

' ll-cr to cr

\ as early as possible we want to know if it is js20, js21 or bimini
\ u3 = js20; u4 = js21/bimini
\ the difference if bimini or js21 will be done later depending if
\ obsidian or citrine is found
\ f8000000 is probably the place of the u3/u4 version
f8000000 rl@ CONSTANT uni-n-version
uni-n-version 4 rshift  dup 3 = CONSTANT u3?  4 = CONSTANT u4?
\ if (f4000682 >> 4) == 1... it is a bimini...
f4000682 rb@ 4 rshift 1 = CONSTANT bimini?

\ to decide wether vga initialisation using bios emulation should be attempted,
\ we need to know wether a vga-device was found during pci-scan.
\ If it is found, this value will be set to the device's phandle
0 value vga-device-node?

\ planar-id reads back GPIO 29 30 31 and returns it as one value
\ if planar-id >= 5 it should be GA2 else it is GA1 (JS20 only)
defer planar-id  ( -- planar-id )

: (planar-id)  ( -- planar-id)
   \ default implementation of planar-id just returns 8
   \ the highest possible planar id for JS20 is 7
   8
;

' (planar-id) to planar-id

#include "header.fs"

\ I/O accesses.
#include "io.fs"

\ XXX: Enable first UART on JS20, scripts forget to do this.  Sigh.
3 7 siocfg!  1 30 siocfg!

#include "serial.fs"

cr

#include "base.fs"

\ Little-endian accesses.  Also known as `wrong-endian'.
#include <little-endian.fs>

\ do not free-mem if address is not within the heap
\ workaround for NVIDIA card
: free-mem  (  addr len -- )
   over heap-start heap-end within  IF
      free-mem
   ELSE
      2drop
   THEN
;

: #join  ( lo hi #bits -- x )  lshift or ;
: #split ( x #bits -- lo hi )  2dup rshift dup >r swap lshift xor r> ;

: blink ;

: reset-dual-emit ;

: console-clean-fifo ;

: bootmsg-nvupdate ;

: asm-cout 2drop drop ;

#include "logging.fs"

: log-string 2drop ;

#include "bootmsg.fs"

000 cp

\ disable the nvram logging until we know if we are
\ running from ram/takeover/js20 or in normal mode on js21
: (nvramlog-write-byte)  drop ;
' (nvramlog-write-byte) to nvramlog-write-byte

#include "exception.fs"

: mm-log-warning 2drop ;

: write-mm-log ( data length type -- status )
	3drop 0
;

080 cp

#include "rtc.fs"

100 cp

\ Input line editing.
#include "accept.fs"

120 cp

#include "dump.fs"

cistack ciregs >r1 ! \ kernel wants a stack :-)

#include "romfs.fs"

140 cp
#include "flash.fs"

\ 1 temp; 0 perm; let's default to temp
1 VALUE flashside?

\ claim the memory used by copy of the flash
flash-header  IF
   romfs-base dup flash-image-size 0 claim drop
THEN

s" bootinfo" romfs-lookup drop c + l@ CONSTANT start-addr
start-addr flash-addr <> CONSTANT takeover?

takeover? u3? or 0=  IF
   \ we want nvram logging to work
   ['] .nvramlog-write-byte to nvramlog-write-byte
THEN

160 cp

u4? IF f8002100 rl@ 0= ELSE false THEN  ?INCLUDE u4-mem.fs
u3?  IF
   planar-id 5 >=  IF
      40000 to nvram-size
   ELSE
      \ change nvram-size to 8000 for GA1 blades
      8000 to nvram-size
   THEN
THEN


takeover?  IF
   \ potentially coming from phype
   u4?  IF
      \ takeover on JS21 is using some nvram area
      \ which might be available
      \ on JS20 the nvram is too small and
      \ we just overwrite the nvram
      sec-nvram-base to nvram-base
   THEN
   sec-nvram-size to nvram-size
   \ in takeover mode the nvram is probably not mapped
   \ to the exact location where the nvram starts
   \ doing a small check to see if we have a partition
   \ starting with 70; this test is far from perfect but
   \ takeover is not the most common mode of running slof
   nvram-base rb@ 70 <>  IF  0 nvram-base rb!  THEN
THEN

200 cp

#include <slof-logo.fs>
#include <banner.fs>

: .banner .slof-logo .banner ;

\ Get the secondary CPUs into our own spinloop.
f8000050 rl@ CONSTANT master-cpu
\ cr .( The master cpu is #) master-cpu .

VARIABLE cpu-mask
: get-slave ( n -- online? )
  0 3ff8 ! 18 lshift 30000000 or 48003f02 over l! icbi 10000 0 DO LOOP 3ff8 @ ;
: mark-online ( n -- )  1 swap lshift cpu-mask @ or cpu-mask ! ;
: get-slaves  40 0 DO i get-slave IF i mark-online THEN LOOP ;
: cpu-report  ( -- )
   cpu-mask @ 40 0  DO  dup 1 and  IF  ." #" i .  THEN  1 rshift  LOOP  drop
;

220 cp
master-cpu mark-online get-slaves

DEFER disable-watchdog ( -- )
DEFER find-boot-sector ( -- )


240 cp
\ Timebase frequency, in Hz.
\ -1 VALUE tb-frequency
d# 14318378 VALUE tb-frequency   \ default value - needed for "ms" to work
-1 VALUE cpu-frequency

#include "helper.fs"
260 cp

#include <timebase.fs>

270 cp

#include <fcode/evaluator.fs>

280 cp

\ rtas-config is not used
0 CONSTANT rtas-config

#include "rtas.fs"
290 cp
s" update_flash.fs" included
2a0 cp
cpu-mask @ rtas-fetch-cpus drop

: of-start-cpu rtas-start-cpu ;

' power-off to halt
' rtas-system-reboot to reboot

: other-firmware  rtas-get-flashside 0= IF 1 ELSE 0 THEN rtas-set-flashside reboot ;
: disable-boot-watchdog rtas-stop-bootwatchdog drop ;
' disable-boot-watchdog to disable-watchdog

true value bmc?
false value debug-boot?

\ for JS21/Bimini try to detect BMC... if kcs (io @ca8) status is not ff...
u4? IF ca8 4 + io-c@ ff = IF false to bmc? true to debug-boot? THEN THEN

VARIABLE memnode

\ Hook to help loading our secondary boot loader.
DEFER disk-read ( lba cnt addr -- )
0 VALUE disk-off

create vpd-cb 24 allot
create vpd-bootlist 4 allot
2c0 cp
#include "ipmi-vpd.fs"
2e0 cp
#include <quiesce.fs>
300 cp
#include <usb/usb-static.fs>
320 cp
#include <scsi-loader.fs>
#include <root.fs>
360 cp
#include "tree.fs"

: .system-information  ( -- )
   s"                   " type cr
   s" SYSTEM INFORMATION" type cr
   s"  Processor  = " type s" cpu" get-chosen  IF
      drop l@ >r pvr@ s" pvr>name" r> $call-method type
      s"  @ " type cpu-frequency d# 1000000 /
      decimal . hex s" MHz" type
   THEN  cr s"  I/O Bridge = " type u3?  IF
      s" U3"  ELSE  s" U4"  THEN type
   f8000000 rl@ 4 rshift s"  (" type 1 0.r s" ." type
   f8000000 rl@ f and 1 0.r s" )" type cr
   s"  SMP Size   = " type cpu-mask @ cnt-bits 1 0.r
   s"  (" type cpu-report 8 emit s" )" type
   cr s"  Boot-Date  = " type .date cr
   s"  Memory     = " type s" memory" get-chosen  IF
      drop l@ s" mem-report" rot $call-method  THEN
   cr s"  Board Type = " type u3?  IF
      s" JS20(GA" type planar-id 5 >=  IF
         s" 2)" ELSE s" 1)" THEN type
   ELSE bimini?  IF  s" Bimini"  ELSE  s" JS21"  THEN  type  THEN
   s"  (" type .vpd-machine-type [char] / emit
   .vpd-machine-serial [char] / emit
   .vpd-hw-revision 8 emit  s" )" type cr
   s"  MFG Date   = " type .vpd-manufacturer-date cr
   s"  Part No.   = " type .vpd-part-number cr
   s"  FRU No.    = " type .vpd-fru-number cr
   s"  FRU Serial = " type .vpd-cardprefix-serial .vpd-card-serial cr
   s"  UUID       = " type .vpd-uuid cr
   s"  Flashside  = " type rtas-get-flashside 0=  IF
      ." 0 (permanent)"
   ELSE
      ." 1 (temporary)" THEN cr
   s"  Version    = " type 
   takeover?  IF
      romfs-base 38 + a type
   ELSE
      slof-build-id here swap rmove 
      here slof-build-id nip type cr
      s"  Build Date = " type bdate2human type
   THEN
   cr cr
;

800 cp

#include "nvram.fs"
takeover? not u4? and  IF
   \ if were are not in takeover mode the nvram should look
   \ something like this:
   \ type  size  name
   \ ========================
   \  51  20000  ibm,CPU0log
   \  51   5000  ibm,CPU1log
   \  70   1000  common
   \  7f  da000  <free-space>
   \ the partition with the type 51 should have been added
   \ by LLFW... if it does not exist then something went
   \ wrong and we just destroy the whole thing
   51 get-nvram-partition IF  0 0 nvram-c!  ELSE  2drop  THEN
THEN

880 cp

\ dmesg/dmesg2 not available if running in takeover/ram mode or on js20
: dmesg  ( -- )  u3? takeover? or 0=  IF  dmesg  THEN ;
: dmesg2  ( -- )  u3? takeover? or 0=  IF  dmesg2  THEN ;

#include "envvar.fs"
check-for-nvramrc

8a0 cp
\ The client interface.
#include "client.fs"
\ ELF binary file format.
#include "elf.fs"
#include <loaders.fs>

8a8 cp

\ check wether a VGA device was found during pci scan, if it was
\ try to initialize it and create the needed device-nodes
0 value biosemu-vmem
100000 value biosemu-vmem-size
0 value screen-info

: init-vga-devices  ( -- )
   vga-device-node? 0= use-biosemu? 0= OR IF
      EXIT
   THEN
   s" VGA Device found: " type vga-device-node? node>path type s"  initializing..." type cr
   \ claim virtual memory for biosemu of 1MB
   biosemu-vmem-size 4 claim to biosemu-vmem
   \ claim memory for screen-info struct (140 bytes)
   d# 140 4 claim to screen-info
   \ remember current-node (it might be node 0 so we cannot use get-node)
   current-node @
   \ change into vga device node
   vga-device-node? set-node
   \ run biosemu to initialize the vga card
   \ s" Time before biosemu:" type .date cr
   vga-device-node? node>path ( pathstr len )
   s" biosemu " biosemu-vmem $cathex ( pathstr len paramstr len )
   20 char-cat \ add a space ( pathstr len paramstr len )
   biosemu-vmem-size $cathex \ add VMEM Size ( pathstr len paramstr len )
   20 char-cat \ add a space ( pathstr len paramstr len )
   2swap $cat ( paramstr+path len )
   biosemu-debug 0<> IF
      20 char-cat biosemu-debug $cathex \ add biosemu-debug as param
      ( paramstr+path+biosemu-debug len )
   THEN
   .(client-exec) IF
      ." biosemu client exec failed!" cr
      set-node                          \ restore old current-node
      EXIT
   THEN
   \ s" Time after biosemu:" type .date cr
   s" VGA initialization: detecting displays..." type cr
   \ try to get info for two monitors
   2 0 DO 
      \ setup screen-info struct as input to get_vbe_info
      s" DDC" 0 char-cat screen-info swap move \ null-terminated "DDC" as signature
      d# 140 screen-info 4 + w! \ reserved size in bytes (see claim above)
      i screen-info 6 + c! \ monitor number
      \ 320 screen-info 7 + w! \ max. screen width (800)
      500 screen-info 7 + w! \ max. screen width (1280)
      \ following line would be the right thing to do, however environment seems not setup yet...
      \ screen-#columns char-width * 500 min 280 max screen-info 7 + w! \ max. screen width, calculated from environment variable screen-#columns, but max. 1280, min. 640...
      8 screen-info 9 + c! \ requested color depth (8bpp)
      \ d# 16 screen-info 9 + c! \ requested color depth (16bpp)
      \ execute get_vbe_info from load-base
      \ s" Time before client exec:" type .date cr
      \ since node>path overwrites strings created with s" 
      \ we need to call it before assembling the parameter string
      vga-device-node? node>path ( pathstr len )
      s" get_vbe_info " biosemu-vmem $cathex ( pathstr len paramstr len )
      20 char-cat \ add a space ( pathstr len paramstr len )
      biosemu-vmem-size $cathex \ add VMEM Size ( pathstr len paramstr len )
      20 char-cat \ add a space ( pathstr len paramstr len )
      2swap $cat ( paramstr+path len )
      20 char-cat
      screen-info $cathex
      .(client-exec) 0=
      \ s" Time after client exec:" type .date cr
      screen-info c@ 0<> AND IF
        s"   display " type i . s" found..." type 
        \ screen found
        \ create device entry
        get-node node>name \ get current nodes name (e.g. "vga") ( str len )
        i \ put display-num on the stack ( str len displaynum )
        new-device \ create new device
           s" vga-display.fs" included
        finish-device
        s" created." type cr
      THEN
   LOOP
   \ return to where we were before changing to vga device node
   set-node
   \ release the claimed memory
   screen-info d# 140 release 
   biosemu-vmem biosemu-vmem-size release

   s" VGA initialization done." type cr
;

init-vga-devices

: enable-framebuffer-output  ( -- )
\ enable output on framebuffer
   s" screen" find-alias ?dup  IF
      \ we need to open/close the screen device once
      \ before "ticking" display-emit to emit
      open-dev close-node
      s" display-emit" $find  IF 
         to emit 
      ELSE
         2drop
      THEN
   THEN
;

enable-framebuffer-output

8b0 cp

\ do not let the usb scan overwrite the atapi cdrom alias
\ pci-cdrom-num TO cdrom-alias-num
usb-scan

: create-aliases  ( -- )
   s" net" s" net1" find-alias ?dup  IF  set-alias ELSE 2drop  THEN
   s" disk" s" disk0" find-alias ?dup  IF  set-alias  ELSE  2drop  THEN
   s" cdrom" s" cdrom0" find-alias ?dup  IF  set-alias  ELSE  2drop  THEN
;

create-aliases

8ff cp

.system-information

: directserial
u3? IF
	s" /ht/isa/serial@3f8" io
ELSE
	s" direct-serial?" evaluate IF s" /ht/isa/serial@2f8" io ELSE s" /ht/isa/serial@3f8" io THEN
THEN
;

directserial
  
\ on bimini we want to automatically enable screen and keyboard, if they are detected...
bimini? IF
   key? IF
      cr ."    input available on current console input device, not switching input / output." cr
   ELSE
      \ this enables the framebuffer as primary output device
      s" screen" find-alias  IF  drop
         s" screen" output
         \ at this point serial output is theoretically disabled
         ."    screen detected and set as default output device" cr
      THEN
      \ enable USB keyboard
      s" keyboard" find-alias  IF  drop
         s" keyboard" input
         \ at this point serial input is disabled
         ."    keyboard detected and set as default input device" cr cr cr
         s"   Press 's' to enter Open Firmware." type cr
         500 ms
      THEN
   THEN
THEN

: .flashside
   cr ." The currently active flashside is: "
   rtas-get-flashside 0= IF ." 0 (permanent)" ELSE
   ." 1 (temporary)" THEN
;

bmc? IF  disable-watchdog  THEN

: flashsave  ( "{filename}" -- rc )
  (parse-line) dup 0> IF
    s" netsave "             \ command
    get-flash-base $cathex   \ Flash base addr
    s"  400000 " $cat        \ Flash size (4MB)
    2swap $cat               \ add parameters from (parse-line)
    evaluate
  ELSE
    cr
    ." Usage: flashsave [bootp|dhcp,]filename[,siaddr][,ciaddr][,giaddr][,bootp-retries][,tftp-retries][,use_ci]"
    cr 2drop
  THEN
;

#include <vpd-bootlist.fs>

\ for the blades we read the bootlist from the VPD
bimini? takeover? or 0=  IF  ['] vpd-boot-import to read-bootlist  THEN

\ for the bimini, we try to boot from disk, if it exists, 
\ only if "boot-device" is not set in the nvram
: bimini-bootlist
   \ check nvram
   s" boot-device" evaluate swap drop ( boot-device-strlen )
   0= IF
      \ no boot-device set in NVRAM, check if disk is available and set it...
      \ clear boot-device list
      0 0 set-boot-device
      s" disk" find-alias ?dup IF
         \ alias found, use it as default
         add-boot-device
      THEN
   THEN
;

bimini? IF ['] bimini-bootlist to read-bootlist THEN

#include <start-up.fs>

#include <boot.fs>

cr .(   Welcome to Open Firmware)
cr
#include "copyright-oss.fs"
cr

\ this CATCH is to ensure the code bellow always executes:  boot may ABORT!
' start-it CATCH drop

#include <history.fs>
nvram-history? [IF]
." loading shell history .. "
history-load
." done" cr
[THEN]

