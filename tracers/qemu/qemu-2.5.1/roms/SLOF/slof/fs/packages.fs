\ *****************************************************************************
\ * Copyright (c) 2004, 2015 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/


\ =============================================================================
\                               SUPPORT PACKAGES
\ =============================================================================


s" packages" device-name
get-node to packages

\   new-device
\   #include "packages/filler.fs"
\   finish-device

new-device
#include "packages/deblocker.fs"
finish-device

new-device
#include "packages/disk-label.fs"
finish-device

new-device
#include "packages/fat-files.fs"
finish-device

new-device
#include "packages/rom-files.fs"
finish-device

new-device
#include "packages/ext2-files.fs"
finish-device

new-device
#include "packages/obp-tftp.fs"
finish-device

new-device
#include "packages/iso-9660.fs"
finish-device
