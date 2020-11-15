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

my-space assign-all-device-bars
my-space pci-device-props
my-space pci-set-irq-line

\ set Memory Write and Invalidate Enable, SERR# Enable (see PCI 3.0 Spec Chapter 6.2.2 device control)
7 4 config-w!

\ Citrine storage controller.
s" obsidian"

include citrine.fs
