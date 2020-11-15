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

\ IO-APIC init

s" io-apic" 2dup device-name device-type
my-space pci-class-name type s"  ( 8131 IO-APIC )" type

pci-io-enable
pci-mem-enable
pci-master-enable

my-space b rshift  \ Get slot #.
dup c lshift fec00000 or  \ Calculate base address.
dup 48 config-l! 0 4c config-l!  \ Set base address.
03 44 config-b!  \ Enable IO-APIC.

s" ioapic.fs" included

2 lshift 14 +  \ Calculate first IRQ #.
init-ioapic  \ Set IRQs.

my-space pci-device-props

cr
