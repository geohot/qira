\ *****************************************************************************
\ * Copyright (c) 2004, 2014 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ DMA memory allocation functions
: dma-alloc ( size -- virt )
   my-phandle TO calling-child
   s" dma-alloc" my-phandle parent $call-static
   0 TO calling-child
;

: dma-free ( virt size -- )
   my-phandle TO calling-child
   s" dma-free" my-phandle parent $call-static
   0 TO calling-child
;

: dma-map-in ( virt size cacheable? -- devaddr )
   my-phandle TO calling-child
   s" dma-map-in" my-phandle parent $call-static
   0 TO calling-child
;

: dma-map-out ( virt devaddr size -- )
   my-phandle TO calling-child
   s" dma-map-out" my-phandle parent $call-static
   0 TO calling-child
;
