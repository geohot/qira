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

my-space pci-device-generic-setup

my-space pci-class-name device-type

\ add legacy I/O Ports / Memory regions to assigned-addresses
\ see PCI Bus Binding Revision 2.1 Section 7.
s" reg" get-my-property
IF
   \ "reg" does not exist, create new
   encode-start
ELSE
   \ "reg" does exist, copy it 
   encode-bytes
THEN
\ I/O Range 0x3B0-0x3BB
my-space a1000000 or encode-int+ \ non-relocatable, aliased I/O space
3b0 encode-64+ \ addr
c encode-64+ \ size
\ I/O Range 0x3C0-0x3DF
my-space a1000000 or encode-int+ \ non-relocatable, aliased I/O space
3c0 encode-64+ \ addr
20 encode-64+ \ size
\ the U4 does not support memory accesses to this region... so we dont put it into "reg"
\ maybe with some clever hacking of the address map registers it will be possible to access
\ these regions??
\ Memory Range 0xA0000-0xBFFFF
\ my-space a2000000 or encode-int+ \ non-relocatable, <1MB Memory space
\ a0000 encode-64+ \ addr
\ 20000 encode-64+ \ size

s" reg" property \ store "reg" property

\ check wether we have already found a vga-device (vga-device-node? != 0) and if
\ this device has Expansion ROM
vga-device-node? 0= 30 config-l@ 0<> AND IF
   \ remember this vga device's phandle
   get-node to vga-device-node?
THEN

cr

