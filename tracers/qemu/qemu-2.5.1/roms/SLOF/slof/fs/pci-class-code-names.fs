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

: pci-class-name-00 ( addr -- str len )
        pci-class@ 8 rshift FF and CASE
        01  OF s" display"               ENDOF
        dup OF s" unknown-legacy-device" ENDOF
        ENDCASE
;

: pci-class-name-01 ( addr -- str len )
        pci-class@ 8 rshift FF and CASE
        00  OF s" scsi"         ENDOF
        01  OF s" ide"          ENDOF
        02  OF s" fdc"          ENDOF
        03  OF s" ipi"          ENDOF
        04  OF s" raid"         ENDOF
        05  OF s" ata"          ENDOF
        06  OF s" sata"         ENDOF
        07  OF s" sas"          ENDOF
        dup OF s" mass-storage" ENDOF
        ENDCASE
;

: pci-class-name-02 ( addr -- str len )
        pci-class@ 8 rshift FF and CASE
        00  OF s" ethernet"   ENDOF
        01  OF s" token-ring" ENDOF
        02  OF s" fddi"       ENDOF
        03  OF s" atm"        ENDOF
        04  OF s" isdn"       ENDOF
        05  OF s" worldfip"   ENDOF
        05  OF s" picmg"      ENDOF
        dup OF s" network"    ENDOF
        ENDCASE
;

: pci-class-name-03 ( addr -- str len )
        pci-class@ FFFF and CASE
        0000  OF s" vga"             ENDOF
        0001  OF s" 8514-compatible" ENDOF
        0100  OF s" xga"             ENDOF
        0200  OF s" 3d-controller"   ENDOF
        dup OF s" display"           ENDOF
        ENDCASE
;

: pci-class-name-04 ( addr -- str len )
        pci-class@ 8 rshift FF and CASE
        00  OF s" video"             ENDOF
        01  OF s" sound"             ENDOF
        02  OF s" telephony"         ENDOF
        dup OF s" multimedia-device" ENDOF
        ENDCASE
;

: pci-class-name-05 ( addr -- str len )
        pci-class@ 8 rshift FF and CASE
        00  OF s" memory"            ENDOF
        01  OF s" flash"             ENDOF
        dup OF s" memory-controller" ENDOF
        ENDCASE
;

: pci-class-name-06 ( addr -- str len )
        pci-class@ 8 rshift FF and CASE
        00  OF s" host"                 ENDOF
        01  OF s" isa"                  ENDOF
        02  OF s" eisa"                 ENDOF
        03  OF s" mca"                  ENDOF
        04  OF s" pci"                  ENDOF
        05  OF s" pcmcia"               ENDOF
        06  OF s" nubus"                ENDOF
        07  OF s" cardbus"              ENDOF
        08  OF s" raceway"              ENDOF
        09  OF s" semi-transparent-pci" ENDOF
        0A  OF s" infiniband"           ENDOF
        dup OF s" unkown-bridge"        ENDOF
        ENDCASE
;

: pci-class-name-07 ( addr -- str len )
        pci-class@ FFFF and CASE
        0000  OF s" serial"                   ENDOF
        0001  OF s" 16450-serial"             ENDOF
        0002  OF s" 16550-serial"             ENDOF
        0003  OF s" 16650-serial"             ENDOF
        0004  OF s" 16750-serial"             ENDOF
        0005  OF s" 16850-serial"             ENDOF
        0006  OF s" 16950-serial"             ENDOF
        0100  OF s" parallel"                 ENDOF
        0101  OF s" bi-directional-parallel"  ENDOF
        0102  OF s" ecp-1.x-parallel"         ENDOF
        0103  OF s" ieee1284-controller"      ENDOF
        01FE  OF s" ieee1284-device"          ENDOF
        0200  OF s" multiport-serial"         ENDOF
        0300  OF s" modem"                    ENDOF
        0301  OF s" 16450-modem"              ENDOF
        0302  OF s" 16550-modem"              ENDOF
        0303  OF s" 16650-modem"              ENDOF
        0304  OF s" 16750-modem"              ENDOF
        0400  OF s" gpib"                     ENDOF
        0500  OF s" smart-card"               ENDOF
        dup   OF s" communication-controller" ENDOF
        ENDCASE
;


: pci-class-name-08 ( addr -- str len )
        pci-class@ FFFF and CASE
        0000  OF s" interrupt-controller" ENDOF
        0001  OF s" isa-pic"              ENDOF
        0002  OF s" eisa-pic"             ENDOF
        0010  OF s" io-apic"              ENDOF
        0020  OF s" iox-apic"             ENDOF
        0100  OF s" dma-controller"       ENDOF
        0101  OF s" isa-dma"              ENDOF
        0102  OF s" eisa-dma"             ENDOF
        0200  OF s" timer"                ENDOF
        0201  OF s" isa-system-timer"     ENDOF
        0202  OF s" eisa-system-timer"    ENDOF
        0300  OF s" rtc"                  ENDOF
        0301  OF s" isa-rtc"              ENDOF
        0400  OF s" hot-plug-controller"  ENDOF
        0500  OF s" sd-host-conrtoller"   ENDOF
        dup   OF s" system-periphal"      ENDOF
        ENDCASE
;

: pci-class-name-09 ( addr -- str len )
        pci-class@ 8 rshift FF and CASE
        00  OF s" keyboard"         ENDOF
        01  OF s" pen"              ENDOF
        02  OF s" mouse"            ENDOF
        03  OF s" scanner"          ENDOF
        04  OF s" gameport"         ENDOF
        dup OF s" input-controller" ENDOF
        ENDCASE
;

: pci-class-name-0A ( addr -- str len )
        pci-class@ 8 rshift FF and CASE
        00  OF s" dock"            ENDOF
        dup OF s" docking-station" ENDOF
        ENDCASE
;

: pci-class-name-0B ( addr -- str len )
        pci-class@ 8 rshift FF and CASE
        00  OF s" 386"           ENDOF
        01  OF s" 486"           ENDOF
        02  OF s" pentium"       ENDOF
        10  OF s" alpha"         ENDOF
        20  OF s" powerpc"       ENDOF
        30  OF s" mips"          ENDOF
        40  OF s" co-processor"  ENDOF
        dup OF s" cpu"           ENDOF
        ENDCASE
;

: pci-class-name-0C ( addr -- str len )
        pci-class@ FFFF and CASE
        0000  OF s" firewire"      ENDOF
        0100  OF s" access-bus"    ENDOF
        0200  OF s" ssa"           ENDOF
        0300  OF s" usb-uhci"      ENDOF
        0310  OF s" usb-ohci"      ENDOF
	0320  OF s" usb-ehci"      ENDOF
        0330  OF s" usb-xhci"      ENDOF
        0380  OF s" usb"           ENDOF
        03FE  OF s" usb-device"    ENDOF
        0400  OF s" fibre-channel" ENDOF
        0500  OF s" smb"           ENDOF
        0600  OF s" infiniband"    ENDOF
        0700  OF s" ipmi-smic"     ENDOF
        0701  OF s" ipmi-kbrd"     ENDOF
        0702  OF s" ipmi-bltr"     ENDOF
        0800  OF s" sercos"        ENDOF
        0900  OF s" canbus"        ENDOF
        dup OF s" serial-bus"      ENDOF
        ENDCASE
;

: pci-class-name-0D ( addr -- str len )
        pci-class@ 8 rshift FF and CASE
        00  OF s" irda"                ENDOF
        01  OF s" consumer-ir"         ENDOF
        10  OF s" rf-controller"       ENDOF
        11  OF s" bluetooth"           ENDOF
        12  OF s" broadband"           ENDOF
        20  OF s" enet-802.11a"        ENDOF
        21  OF s" enet-802.11b"        ENDOF
        dup OF s" wireless-controller" ENDOF
        ENDCASE
;


: pci-class-name-0E ( addr -- str len )
        pci-class@ 8 rshift FF and CASE
        dup OF s" intelligent-io" ENDOF
        ENDCASE
;

: pci-class-name-0F ( addr -- str len )
        pci-class@ 8 rshift FF and CASE
        01  OF s" satelite-tv"     ENDOF
        02  OF s" satelite-audio"  ENDOF
        03  OF s" satelite-voice"  ENDOF
        04  OF s" satelite-data"   ENDOF
        dup OF s" satelite-devoce" ENDOF
        ENDCASE
;

: pci-class-name-10 ( addr -- str len )
        pci-class@ 8 rshift FF and CASE
        00  OF s" network-encryption"       ENDOF
        01  OF s" entertainment-encryption" ENDOF
        dup OF s" encryption"               ENDOF
        ENDCASE
;

: pci-class-name-11 ( addr -- str len )
        pci-class@ 8 rshift FF and CASE
        00  OF s" dpio"                       ENDOF
        01  OF s" counter"                    ENDOF
        10  OF s" measurement"                ENDOF
        20  OF s" managment-card"             ENDOF
        dup OF s" data-processing-controller" ENDOF
        ENDCASE
;

\ create a string holding the predefined Class-Code-Names
: pci-class-name ( addr -- str len )
        dup pci-class@ 10 rshift CASE
        00  OF pci-class-name-00 ENDOF
        01  OF pci-class-name-01 ENDOF
        02  OF pci-class-name-02 ENDOF
        03  OF pci-class-name-03 ENDOF
        04  OF pci-class-name-04 ENDOF
        05  OF pci-class-name-05 ENDOF
        06  OF pci-class-name-06 ENDOF
        07  OF pci-class-name-07 ENDOF
        08  OF pci-class-name-08 ENDOF
        09  OF pci-class-name-09 ENDOF
        0A  OF pci-class-name-0A ENDOF
        0B  OF pci-class-name-0B ENDOF
        0C  OF pci-class-name-0C ENDOF
        0C  OF pci-class-name-0D ENDOF
        0C  OF pci-class-name-0E ENDOF
        0C  OF pci-class-name-0F ENDOF
        0C  OF pci-class-name-10 ENDOF
        0C  OF pci-class-name-11 ENDOF
        dup OF drop s" unknown"  ENDOF
        ENDCASE
;
