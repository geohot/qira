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

\ This struct must match "struct virtio_device" in virtio.h!
STRUCT
   /n FIELD vd>base
   /l FIELD vd>type
CONSTANT /vd-len


\ Initialize virtiodev structure for the current node
: virtio-setup-vd  ( vdstruct -- )
   >r
   \ Does it have a "class-code" property? If yes, assume we're a PCI device
   s" class-code" get-node get-property 0= IF
      \ Set up for PCI device interface
      2drop
      s" 10 config-l@ translate-my-address 3 not AND" evaluate
      ( io-base ) r@ vd>base !
      0 r@ vd>type l!
   ELSE
      ." unsupported virtio interface!" cr
      1 r@ vd>type l!
   THEN
   r> drop
;
