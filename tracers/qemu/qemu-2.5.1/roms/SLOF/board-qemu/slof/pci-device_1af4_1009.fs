\ *****************************************************************************
\ * Copyright (c) 2011 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ Handle virtio-fs device

s" virtio [ network ]" type cr

my-space pci-device-generic-setup

pci-master-enable
pci-mem-enable
pci-io-enable

s" virtio-fs.fs" included

\ Allocate memory for virtio queue:
virtiodev 0 virtio-get-qsize virtio-vring-size
1000 CLAIM VALUE queue-addr

\ Write queue address into device:
queue-addr c rshift
virtiodev vd>base @ 8 +
rl!-le

pci-device-disable
