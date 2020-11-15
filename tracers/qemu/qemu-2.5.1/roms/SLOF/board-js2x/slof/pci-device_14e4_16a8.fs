\ *****************************************************************************
\ * Copyright (c) 2013 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ Handle bcm57xx device

s" bcm57xx [ net ]" type cr

my-space pci-device-generic-setup

pci-io-enable

s" bcm57xx.fs" included

pci-device-disable
