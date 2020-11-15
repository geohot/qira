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

\ the defaults
\ some of those are platform dependent, and should e.g. be
\ created from VPD values
true default-flag auto-boot?
s" " default-string boot-device
s" " default-string boot-file
s" boot" default-string boot-command
s" " default-string diag-device
s" " default-string diag-file
false default-flag diag-switch?
true default-flag fcode-debug?
s" " default-string input-device
s" " default-string nvramrc
s" " default-string oem-banner
false default-flag oem-banner?
0 0 default-bytes oem-logo
false default-flag oem-logo?
s" " default-string output-device
200 default-int screen-#columns
200 default-int screen-#rows
0 default-int security-#badlogins
0 default-secmode security-mode
s" " default-string security-password
0 default-int selftest-#megs
false default-flag use-nvramrc?
false default-flag direct-serial?
true default-flag real-mode?
default-load-base default-int load-base
#ifdef BIOSEMU
true default-flag use-biosemu?
0 default-int biosemu-debug
#endif
