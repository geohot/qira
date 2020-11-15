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


s" /packages" find-device

new-device
   s" sms" device-name

   : open true ;

   : close ;

   \ The rest of methods is loaded dynamically from the romfs
   \ on a first call to sms-start

finish-device

device-end \ leave /packages

