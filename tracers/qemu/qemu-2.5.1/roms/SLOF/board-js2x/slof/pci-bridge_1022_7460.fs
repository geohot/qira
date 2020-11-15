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

\ AMD 8111 I/O hub.

\ See the documentation at http://www.amd.com ; the datasheet for this chip is
\ document #24674.

\ Config space access functions - we're touching multiple device numbers and
\ device functions below, so we've got to add our own my-space base here:
: config-b@  dup 1000 < IF my-space + THEN config-b@ ;
: config-w@  dup 1000 < IF my-space + THEN config-w@ ;
: config-l@  dup 1000 < IF my-space + THEN config-l@ ;
: config-b!  dup 1000 < IF my-space + THEN config-b! ;
: config-w!  dup 1000 < IF my-space + THEN config-w! ;
: config-l!  dup 1000 < IF my-space + THEN config-l! ;

\ First, some master config.  Not all of this logically belongs to just
\ one function, and certainly not to the LPC bridge; also, we'll
\ initialize all functions in "downstream" order, and this code has to be
\ run first.  So do it now.

00 842 config-b! \ Disable 8237 & 8254 & 8259's.  We're not a PC.
u3?  IF
   80 847 config-b! \ Disable EHCI, as it is terminally broken.
THEN
03 848 config-b! \ Enable LPC, IDE; disable I2C, SMM, AC'97 functions.
01 849 config-b! \ Enable USB, disable 100Mb enet.
01 84b config-b! \ Enable IO-APIC.

fec00000 s" ioapic.fs" included
00 init-ioapic

\ Program PNPIRQ[0,1,2] as IRQ #D,E,F; switch those GPIOs to low-active.
  0b 848 config-b! \ enable devB:3
7000 b58 config-l! \ map PMxx at pci i/o 7000
  d1 b41 config-b! \ enable access to PMxx space

\ on JS20 the planar id is encoded in GPIO 29, 30 and 31
\ >=5 is GA2 else it is GA1
: (planar-id) ( -- planar-id)
   [ 70dd io-c@ 5 rshift 1 and ]  LITERAL
   [ 70de io-c@ 5 rshift 2 and ]  LITERAL
   [ 70df io-c@ 5 rshift 4 and ]  LITERAL
   + + 7 xor
;

u3?  IF  [']  (planar-id) to planar-id  THEN

8 70d3 io-c!  8 70d4 io-c!  8 70d5 io-c! \ set the pins to low-active
 bimini? IF 5 70c4 io-c! THEN \ on bimini set gpio4 as output and high to power up USB
 fec b44 config-w! \ set PNPIRQ pnpirq2 -> f , pnpirq1 -> e pnpirq0 -> c
  51 b41 config-b! \ disable access to PMxx space
  03 848 config-b! \ disable devB:3

\ The function of the PCI controller BARs change depending on the mode the
\ controller is in.
\ And the default is legacy mode.  Gross.
05 909 config-b! \ Enable native PCI mode.
03 940 config-b! \ Enable both ports.

\ Enable HPET on 8111, at address fe000000.
fe000001 8a0 config-l!

: >hpet  fe000000 + ;
: hpet@  >hpet rl@-le ;
: hpet!  >hpet rl!-le ;

INCLUDE freq.fs

\ Disable HPET.
0 8a0 config-l!

\ 8111 has only 16 bits of PCI I/O space.  Get the address in range.
8000 next-pci-io !

\ before disabling EHCI it needs to be reset

\ first we are setting up the BAR0, so that we can talk to the
\ memory mapped controller; not using the PCI scan because we just
\ want a temporary setup

: really-disable-broken-amd8111-ehci  ( -- )
   \ this word only works on U4 systems (JS21/Bimini)
   \ yeah, hardcoded!
   f2000000 to puid
   
   \ the PCI scan would assign pci-next-mmio to that device
   \ let's just take that address
   pci-next-mmio @ 100000 #aligned 
   \ pci-bus-number 10 lshift 210 or could be something like 70210
   \ 7: pci-bus-number
   \ 2: device function
   \ 10: offset 10 (bar 0)
   pci-bus-number 10 lshift 210 or rtas-config-l!

   \ enable memory space
   pci-bus-number 10 lshift 204 or dup rtas-config-l@ 2 or swap rtas-config-l!

   pci-next-mmio @ 100000 #aligned ( base )

   \ Sequence prescribed for resetting the EHCI contoller

   \ If Run/Stop bit (ECAP30 bit 0) is 1
   \   Set Run/Stop bit to 0
   \   wait 2ms

   dup 30 + rl@ 1 and 1 =  IF
      dup 30 + rl@ 1 or
      over 30 + rl!
      2 ms
   THEN

   \ While HCHalted bit (ECAP34 bit 12) is 0  (still running, wait forever)
   \   wait 2ms

   BEGIN  dup 34 + rl@ 1000 and 0= 2 ms UNTIL

   \ Set HCReset bit (ECAP30 bit 1)

   dup 30 + 2 swap rl!

   \ While HCReset bit is 1 (wait forever for reset to complete)
   \   wait 2ms

   BEGIN  dup 30 + rl@ 2 and 0= 2 ms UNTIL  drop

   \ now it is really disabled

   \ disable memory space access again
   2100000 pci-bus-number 10 lshift 204 or rtas-config-l!

   80 847 config-b! \ Disable EHCI, as it is terminally broken.
;

my-space pci-class-name type cr

\ copied from pci-properties.fs and pci-scan.fs
\ changed to disable the EHCI completely just before the scan
\ and after mem/IO transactions have been enabled

\ Setup the Base and Limits in the Bridge
\ and scan the bus(es) beyond that Bridge
: pci-bridge-probe-amd8111 ( addr -- )
   dup pci-bridge-set-bases                        \ SetUp all Base Registers
   dup pci-bridge-range-props                      \ Setup temporary "range
   pci-bus-number 1+ TO pci-bus-number             \ increase number of busses found
   pci-device-vec-len 1+ TO pci-device-vec-len     \ increase the device-slot vector depth
   dup                                             \ stack config-addr for pci-bus!
   FF swap                                         \ Subordinate Bus Number ( for now to max to open all subbusses )
   pci-bus-number swap                             \ Secondary   Bus Number ( the new busnumber )
   dup pci-addr2bus swap                           \ Primary     Bus Number ( the current bus )
   pci-bus!                                        \ and set them into the bridge
   pci-enable                                      \ enable mem/IO transactions

   \ at this point we can talk to the broken EHCI controller
   really-disable-broken-amd8111-ehci

   dup pci-bus-scnd@ func-pci-probe-bus            \ and probe the secondary bus
   dup pci-bus-number swap pci-bus-subo!           \ set SubOrdinate Bus Number to current number of busses
   pci-device-vec-len 1- TO pci-device-vec-len     \ decrease the device-slot vector depth
   dup pci-bridge-set-limits                       \ SetUp all Limit Registers
   drop                                            \ forget the config-addr
;

\ used to set up all unknown Bridges.
\ If a Bridge has no special handling for setup
\ the device file (pci-bridge_VENDOR_DEVICE.fs) can call
\ this word to setup busses and scan beyond.
: pci-bridge-generic-setup-amd8111 ( addr -- )
   pci-device-slots >r             \ save the slot array on return stack
   dup pci-common-props            \ set the common properties before scanning the bus
   s" pci" device-type             \ the type is allways "pci"
   dup pci-bridge-probe-amd8111    \ find all device connected to it
   dup assign-all-bridge-bars      \ set up all memory access BARs
   dup pci-set-irq-line            \ set the interrupt pin
   dup pci-set-capabilities        \ set up the capabilities
   pci-bridge-props                \ and generate all properties
   r> TO pci-device-slots          \ and reset the slot array
;

: amd8111-bridge-setup
    my-space
    u3? takeover? or  IF
       \ if it is js20 or we are coming from takeover
       \ we just do the normal setup
       pci-bridge-generic-setup
    ELSE
       pci-bridge-generic-setup-amd8111
    THEN
    s" pci" device-name
;

amd8111-bridge-setup
