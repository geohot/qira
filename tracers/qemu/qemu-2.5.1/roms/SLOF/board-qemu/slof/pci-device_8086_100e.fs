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

\ Handle e1000 device

s" e1000 [ net ]" type cr

my-space pci-device-generic-setup

pci-io-enable

s" e1k.fs" included

pci-device-disable
