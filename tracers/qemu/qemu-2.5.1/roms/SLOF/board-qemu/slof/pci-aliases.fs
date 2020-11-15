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

\ Starting alias number for net devices after the onboard devices.
0 VALUE pci-net-num
\ Starting alias number for disks after the onboard devices.
0 VALUE pci-disk-num
\ Starting alias number for cdroms after the onboard devices.
0 VALUE pci-cdrom-num

\ define a new alias for this device
: pci-set-alias ( str-addr str-len num -- )
        $cathex strdup       \ create alias name
        get-node node>path   \ get path string
        set-alias            \ and set the alias
;

\ define a new net alias
: unknown-enet ( -- pci-net-num )
	pci-net-num dup 1+ TO pci-net-num
;
: pci-alias-net ( config-addr -- )
        drop                                   \ forget the config address
        pci-net-num dup 1+ TO pci-net-num      \ increase the pci-net-num
        s" net" rot pci-set-alias              \ create the alias
;

\ define a new disk alias
: pci-alias-disk ( config-addr -- )
        drop                                    \ forget the config address
        pci-disk-num dup 1+ TO pci-disk-num     \ increase the pci-disk-num
        s" disk" rot pci-set-alias              \ create the alias
;
\ define a new cdrom alias
: pci-alias-cdrom ( config-addr -- )
        drop                                    \ forget the config address
        pci-cdrom-num dup 1+ TO pci-cdrom-num     \ increase the pci-cdrom-num
        s" cdrom" rot pci-set-alias              \ create the alias
;

\ define the alias for the calling device
: pci-alias ( config-addr -- )
        dup pci-class@ 
        10 rshift CASE
                01 OF   pci-alias-disk ENDOF
                02 OF   pci-alias-net  ENDOF
               dup OF   drop           ENDOF
        ENDCASE
;
