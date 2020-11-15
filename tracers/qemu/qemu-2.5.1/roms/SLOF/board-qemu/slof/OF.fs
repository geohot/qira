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

\ The master file.  Everything else is included into here.

hex

' ll-cr to cr

#include "header.fs"

#include "hvterm.fs"

#include "base.fs"

\ Set default load-base to 0x4000
4000 to default-load-base

\ Little-endian accesses.  Also known as `wrong-endian'.
#include <little-endian.fs>

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

#include "exception.fs"

: mm-log-warning 2drop ;

: write-mm-log ( data length type -- status )
	3drop 0
;

100 cp

\ Input line editing.
#include "accept.fs"

120 cp

#include "dump.fs"

cistack ciregs >r1 ! \ kernel wants a stack :-)

140 cp

#include "romfs.fs"

200 cp

#include <slof-logo.fs>

201 cp

#include <banner.fs>

: .banner .slof-logo .banner ;

220 cp

DEFER find-boot-sector ( -- )

240 cp
\ Timebase frequency, in Hz. Start with a good default
\ Use device-tree later to fix it up
d# 512000000 VALUE tb-frequency   \ default value - needed for "ms" to work
-1 VALUE cpu-frequency

#include "helper.fs"
260 cp

#include <timebase.fs>

270 cp

#include <fcode/evaluator.fs>

2e0 cp

#include <quiesce.fs>

300 cp

#include <usb/usb-static.fs>

320 cp

#include <scsi-loader.fs>

340 cp

#include "fdt.fs"

360 cp

#include <root.fs>

370 cp

: check-boot-menu
   s" qemu,boot-menu" get-chosen IF
      decode-int 1 = IF
         ." Press F12 for boot menu." cr cr
      THEN
      2drop
   THEN
;
check-boot-menu

380 cp

\ Grab rtas from qemu
#include "rtas.fs"

390 cp

#include "virtio.fs"

3f0 cp

#include "tree.fs"

800 cp

#include "nvram.fs"

880 cp

#include "envvar.fs"
check-for-nvramrc

890 cp

#include "qemu-bootlist.fs"

8a0 cp

\ The client interface.
#include "client.fs"
\ ELF binary file format.
#include "elf.fs"
#include <loaders.fs>

8a8 cp
CREATE version-str 10 ALLOT
0 value temp-ptr

: dump-display-buffer
    disp-ptr to temp-ptr
    " SLOF **********************************************************************" terminal-write drop
    cr
    version-str get-print-version
    version-str @                   \ start
    version-str 8 + @               \ end
    over - terminal-write drop
    " Press 's' to enter Open Firmware." terminal-write drop
    cr cr
    temp-ptr disp-size > IF
	temp-ptr disp-size MOD
	dup
	prevga-disp-buf + swap disp-size swap - terminal-write drop
	temp-ptr disp-size MOD
	prevga-disp-buf swap 1 - terminal-write drop
    ELSE
	prevga-disp-buf temp-ptr terminal-write drop
    THEN
;

: enable-framebuffer-output  ( -- )
\ enable output on framebuffer
   s" screen" find-alias ?dup  IF
      \ we need to open/close the screen device once
      \ before "ticking" display-emit to emit
      open-dev close-node
      false to store-prevga?
      s" display-emit" $find  IF 
         to emit 
	 dump-display-buffer
      ELSE
         2drop
      THEN
   THEN
;

enable-framebuffer-output

8b0 cp

\ Scan USB devices
usb-scan

8c0 cp

\ Claim remaining memory that is used by firmware:
romfs-base 400000 0 ' claim CATCH IF ." claim failed!" cr 2drop THEN drop

8d0 cp

: set-default-console
    s" linux,stdout-path" get-chosen IF
        decode-string
        ." Using default console: " 2dup type cr
        io
        2drop
    ELSE
        ." No console specified "
        " screen" find-alias dup IF nip THEN
        " keyboard" find-alias dup IF nip THEN
	AND IF
	  ." using screen & keyboard" cr
	  " screen" output
	  " keyboard" input
        ELSE
          " hvterm" find-alias IF
	    drop
	    ." using hvterm" cr
            " hvterm" io
	  ELSE
	    " /openprom" find-node ?dup IF
		set-node
		." and no default found, creating dev-null" cr
		" dev-null.fs" included
		" devnull-console" io
		0 set-node
	    THEN
	  THEN
        THEN
    THEN
;
set-default-console

8e0 cp

\ Check if we are booting a kernel passed by qemu, in which case
\ we skip initializing some devices

0 VALUE direct-ram-boot-base
0 VALUE direct-ram-boot-size

: (boot-ram)
    direct-ram-boot-size 0<> IF
        ." Booting from memory..." cr
	s" go-args 2@ " evaluate
	direct-ram-boot-base 0
	s" true state-valid ! " evaluate
	s" disable-watchdog go-64" evaluate
    THEN
;

8e8 cp

: check-boot-from-ram
    s" qemu,boot-kernel" get-chosen IF
        decode-int -rot decode-int -rot ( n1 n2 p s )
	decode-int -rot decode-int -rot ( n1 n2 n3 n4 p s )
	2drop
	swap 20 << or to direct-ram-boot-size
	swap 20 << or to direct-ram-boot-base
	." Detected RAM kernel at " direct-ram-boot-base .
	." (" direct-ram-boot-size . ." bytes) "
	\ Override the boot-command word without touching the
	\ nvram environment
	s" boot-command" $create " (boot-ram)" env-string
    THEN
;
check-boot-from-ram

8ff cp

#include <start-up.fs>

."      "   \ Clear last checkpoint

#include <boot.fs>

cr .(   Welcome to Open Firmware)
cr
#include "copyright-oss.fs"
cr cr

\ this CATCH is to ensure the code bellow always executes:  boot may ABORT!
' start-it CATCH drop

cr ." Ready!"
