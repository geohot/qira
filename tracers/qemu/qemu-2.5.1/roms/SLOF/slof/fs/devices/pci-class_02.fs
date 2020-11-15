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

s" network [ " type my-space pci-class-name type s"  ]" type

my-space pci-device-generic-setup
my-space pci-alias-net

s" network" device-type

cr

INSTANCE VARIABLE obp-tftp-package
: open  ( -- okay? )
   open IF           \ enables PCI mem, io and Bus master and returns TRUE
      my-args s" obp-tftp" $open-package obp-tftp-package ! true
   ELSE
       false
   THEN ;

: close  ( -- )
    obp-tftp-package @ close-package
    close ;         \ disables PCI mem, io and Bus master

: load  ( addr -- len )
    s" load" obp-tftp-package @ $call-method  ;

: ping  ( -- )  s" ping" obp-tftp-package @ $call-method  ;
