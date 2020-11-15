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

\ -----------------------------------------------------------------------------
\ Set the msi address for a device
: pci-set-msi ( cap-addr -- )
        drop
;

\ Set up all known capabilities for this board to the plugged devices
: pci-set-capabilities ( config-addr -- )
        dup 05 pci-cap-find ?dup IF pci-set-msi THEN
        drop
;
