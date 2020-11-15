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

\ define function pointer as forward declaration for get-interrupt-line
\ this is board wireing and southbridge dependent
\ returns the wired interrupt line for this config addr
\ ( config-addr -- irq-line )
DEFER pci-get-irq-line

\ define function pointer as forward declaration for get-interrupt-sense-type
\ this is board wireing and southbridge dependent
\ returns the wired interrupt sense type for this config addr
\ 0 - Edge rising
\ 1 - Level low
\ 2 - Level high
\ 3 - Edge falling
\ ( config-addr -- irq-sense )
DEFER pci-get-irq-sense


\ *****************************************************************************
\ Generic IRQ routines
\ *****************************************************************************



: unknown-slot ( -- 0 )
\	cr pci-vec ABORT" Unknown slot "
	0
;
\ 0c s" /ht/@1/@2"    PCI-X INTA & INTC Pnpirq0 -> irq12
\ 0e s" /ht/@1/@2"    PCI-X INTB & INTD Pnpirq1 -> irq14
\ 10 s" /ht/@8,1"     ATA         
\ 0f s" /ht/@1/@1"    Obsidian     Pnpirq2 -> irq15
\ 10 s" /ht/@7/@2"    Video / Exar Serial  PirqA
\ 11 s" /ht/@2/@4"    Ethernet     PirqB
\ 12 s" /ht/@2/@4,1"  Ethernet     PirqC
\ 13 s" /ht/@7/@0"    USB          PirqD
\ 13 s" /ht/@7/@0,1"  USB          PirqD
\ 13 s" /ht/@7/@0,2"  USB          PirqD

\ 14 s" /ht/@3/@0"    PCIe gpio28
\ 15 s" /ht/@4/@0"    PCIe gpio29
\ 16 s" /ht/@5/@0"    PCIe gpio30
\ 17 s" /ht/@6/@0"    PCIe gpio31


\ -----------------------------------------------------------------------------
\ Get the interrupt pin for a device on ht u4
: u4-get-irq-line ( config-addr -- irq-line )
\	cr s" u4-get-irq-line " type
	pci-device-vec c@ CASE 
		1 OF pci-device-vec-len 1 >= IF  
				pci-device-vec 1+ c@ CASE 
					1 OF f ENDOF
					2 OF dup pci-interrupt@ CASE
							1 OF c ENDOF
							3 OF e ENDOF
							2 OF c ENDOF
							4 OF e ENDOF
						ENDCASE
					ENDOF 
					dup OF unknown-slot  ENDOF
				ENDCASE
			ELSE
				unknown-slot
			THEN
		ENDOF
		2 OF pci-device-vec-len 1 >= IF  
				 pci-device-vec 1+ c@ CASE
					4 OF dup pci-addr2fn 1 >= IF 12 ELSE 11 THEN  ENDOF 
					dup OF unknown-slot  ENDOF
				ENDCASE
			ELSE
				unknown-slot
			THEN
		ENDOF
		3 OF 14 ENDOF
		4 OF 15 ENDOF
		5 OF 16 ENDOF
		6 OF 17 ENDOF
		7 OF pci-device-vec-len 1 >= IF  
				pci-device-vec 1+ c@ CASE 
					0 OF 13  ENDOF 
					2 OF 10  ENDOF 
					dup OF unknown-slot  ENDOF
				ENDCASE
			ELSE
				unknown-slot
			THEN
		ENDOF
		8 OF 10 ENDOF
                dup OF unknown-slot  ENDOF	
        ENDCASE
	swap drop
;

\ -----------------------------------------------------------------------------
\ Get the interrupt sense type for a device on ht u4
: u4-get-irq-sense ( config-addr -- irq-sense )
\	cr s" u4-get-irq-sense " type
        u4-get-irq-line CASE 
	0c OF 00 ENDOF
	0e OF 00 ENDOF
	dup OF 01  ENDOF
        ENDCASE
;

\ 10 s" /ht/@4,1"    set-pci-interrupt \ ATA
\ 13 s" /ht/@3/@0"   set-pci-interrupt \ USB
\ 13 s" /ht/@3/@0,1" set-pci-interrupt \ USB
\ 13 s" /ht/@3/@0,2" set-pci-interrupt \ USB
\ 1c s" /ht/@2/@1"   set-pci-interrupt \ Ethernet
\ 1d s" /ht/@2/@1,1" set-pci-interrupt \ Ethernet

\ -----------------------------------------------------------------------------
\ Get the interrupt pin for a device on ht u3
: u3-get-irq-line ( config-addr -- irq-line )
\	cr s" u3-get-irq-line " type
	pci-device-vec c@ CASE 
		2 OF pci-device-vec-len 1 >= IF  
				pci-device-vec 1+ c@ CASE 
					1 OF dup pci-addr2fn 1 >= IF 1d ELSE 1c THEN  ENDOF 
					dup OF unknown-slot  ENDOF
				ENDCASE
			ELSE
				unknown-slot
			THEN
		ENDOF
		3 OF 13 ENDOF
		4 OF 10 ENDOF
                dup OF unknown-slot  ENDOF	
        ENDCASE
	swap drop
;

\ -----------------------------------------------------------------------------
\ Get the interrupt sense type for a device on ht u3
: u3-get-irq-sense ( config-addr -- irq-sense )
\	cr s" u3-get-irq-sense " type
        u3-get-irq-line CASE 
	dup OF 01  ENDOF
        ENDCASE
;



\ -----------------------------------------------------------------------------
\ Get the interrupt pin for a device on attu
: pcie-get-irq-line ( config-addr -- irq-line )
\	cr s" pcie-get-irq-line " type
	drop
	3
;


\ -----------------------------------------------------------------------------
\ Get the interrupt sense type for a device on attu
: pcie-get-irq-sense ( config-addr -- irq-sense )
\ 	cr s" pcie-get-irq-sense " type
       drop
        01
;

\ -----------------------------------------------------------------------------
\ Set up the special routines for HT irq handling
: ht-irq-init ( -- )
\	cr s" ht-irq-init " type
	u4? IF
       		['] u4-get-irq-line TO pci-get-irq-line
       		['] u4-get-irq-sense TO pci-get-irq-sense
	ELSE
        	['] u3-get-irq-line TO pci-get-irq-line
	       	['] u3-get-irq-sense TO pci-get-irq-sense
	THEN
;

\ -----------------------------------------------------------------------------
\ Set up the special routines for PCI-e irq handling
: pcie-irq-init ( -- )
\	cr s" pcie-irq-init " type
        ['] pcie-get-irq-sense TO pci-get-irq-sense
        ['] pcie-get-irq-line TO pci-get-irq-line
;

\ -----------------------------------------------------------------------------
\ Set up the special routines for irq handling
0 VALUE mpic
: pci-irq-init ( mpic puid -- mpic )
        over TO mpic
        18 rshift FF and
        CASE
                F1 OF pcie-irq-init ENDOF
                F2 OF ht-irq-init ENDOF
                dup OF ABORT" Wrong PUID! in pci-irq-init" ENDOF
        ENDCASE
;

\ -----------------------------------------------------------------------------
\ Set the interrupt pin for a device
: pci-set-irq-line ( config-addr -- )
\	cr pci-vec
        dup pci-get-irq-line 
\	." ->" dup .
        swap pci-irq-line!
;

\ -----------------------------------------------------------------------------
\ Add an irq entry for the device at config-addr into the irq map
\ each entry consists of 7 integer values
\ Structure of an entry:
\             +----------+---+---+------------+--------------+---------+---------------+
\  Number#    |    0     | 1 | 2 |     3      |      4       |    5    |      6        |
\             +----------+---+---+------------+--------------+---------+---------------+
\  meaning    |  config  |   |   |      int#  |  phandle     | intr nr | pos edge (0)  |
\             |   addr   |   |   | (1=a, 2=b, |  intr contr  |         | act ll   (1)  |
\             +----------+---+---+------------+--------------+---------+---------------+
\  value      | pci slot | 0 | 0 |    1       |        mpic  |     7   |     0|1       |
\             +----------+---+---+------------+--------------+---------+---------------+
: pci-gen-irq-entry ( prop-addr prop-len config-addr -- prop-addr prop-len )
        dup >r encode-int+ 0    encode-64+      \ config addr
        r@ pci-interrupt@       encode-int+     \ interrupt type
        mpic                    encode-int+     \ phandle to MPIC
        r@ pci-irq-line@        encode-int+     \ interrupt number
        r> pci-get-irq-sense    encode-int+     \ trigger type
;
