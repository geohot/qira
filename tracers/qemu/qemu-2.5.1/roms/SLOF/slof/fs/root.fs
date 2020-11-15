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

\ this creates the root and common branches of the device tree

defer (client-exec)
defer client-exec

\ defined in slof/fs/client.fs
defer callback
defer continue-client

0 VALUE chosen-node

: chosen
  chosen-node dup 0= IF
    drop s" /chosen" find-node dup to chosen-node
  THEN
;

: set-chosen ( prop len name len -- )
  chosen set-property ;

: get-chosen ( name len -- [ prop len ] success )
  chosen get-property 0= ;

\ Look for an exising root, create one if needed
" /" find-node dup 0= IF
    drop
    new-device
    s" /" device-name
ELSE
    extend-device
THEN

\ Create /chosen if it doesn't exist
" /chosen" find-node dup 0= IF
    drop
    new-device
    s" chosen" device-name
    s" " encode-string s" bootargs" property
    s" " encode-string s" bootpath" property
    finish-device
ELSE
    drop
THEN

\ Create /aliases
new-device
    s" aliases" device-name
finish-device

\ Create /options
new-device
    s" options" device-name
finish-device

\ Create /openprom
new-device
    s" openprom" device-name
    0 0 s" relative-addressing" property
finish-device

\ Create /packages
new-device 
#include <packages.fs>
finish-device

: open true ;
: close ;
#include <archsupport.fs>

\ Finish root
finish-device

