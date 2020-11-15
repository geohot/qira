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

\ this is a C-to-Forth translation from the translate
\ address code in the client
\ with extensions to handle different sizes of #size-cells

\ this tries to figure out if it is a PCI device what kind of
\ translation is wanted
\ if prop_type is 0, "reg" property is used, otherwise "assigned-addresses"
: pci-address-type  ( node address prop_type -- type )
   -rot 2 pick ( prop_type node address prop_type )
   0= IF
      swap s" reg" rot get-property  ( prop_type address data dlen false )
   ELSE
      swap s" assigned-addresses" rot get-property  ( prop_type address data dlen false )
   THEN
   IF  2drop -1  EXIT  THEN  4 / 5 /
   \ advance (phys-addr(3) size(2)) steps
   0 DO
      \ BARs and Expansion ROM must be in assigned-addresses...
      \ so if prop_type is 0 ("reg") and a config space offset is set
      \ we skip this entry...
      dup l@ FF AND 0<> ( prop_type address data cfgspace_offset? )
      3 pick 0= ( prop_type address data cfgspace_offset? reg_prop? )
      AND NOT IF 
         2dup 4 + ( prop_type address data address data' )
         2dup @ 2 pick 8 + @ + <= -rot @  >= and  IF
            l@ 03000000 and 18 rshift nip
            ( prop_type type )
            swap drop ( type )
            UNLOOP EXIT
         THEN
      THEN
      \ advance in 4 byte steps and (phys-addr(3) size(2)) steps
      4 5 * +
   LOOP
   3drop -1
;

: (range-read-cells)  ( range-addr #cells -- range-value )
   \ if number of cells != 1; do 64bit read; else a 32bit read
   1 =  IF  l@  ELSE  @  THEN
;

\ this functions tries to find a mapping for the given address
\ it assumes that if we have #address-cells == 3 that we are trying
\ to do a PCI translation

\ nac - #address-cells
\ nsc - #size-cells
\ pnac - parent #address-cells

: (map-one-range)  ( type range pnac nsc nac address -- address true | address false )
   \ only check for the type if nac == 3 (PCI)
   over 3 = 5 pick l@ 3000000 and 18 rshift 7 pick <> and  IF
      >r 2drop 3drop r> false EXIT
   THEN
   \ get size
   4 pick 4 pick 3 pick + 4 * +
   \ get nsc
   3 pick
   \ read size
   ( type range pnac nsc nac address range nsc )
   (range-read-cells)
   ( type range pnac nsc nac address size )
   \ skip type if PCI
   5 pick 3 pick 3 =  IF
      4 +
   THEN
   \ get nac
   3 pick
   ( type range pnac nsc nac address size range nac )
   \ read child-mapping
   (range-read-cells)
   ( type range pnac nsc nac address size child-mapping )
   dup >r dup 3 pick > >r + over <= r> or  IF
      \ address is not inside the mapping range
      >r 2drop 3drop r> r> drop false EXIT
   THEN
   dup r> -
   ( type range pnac nsc nac address offset )
   \ add the offset on the parent mapping
   5 pick 5 pick 3 =  IF
      \ skip type if PCI
      4 +
   THEN
   3 pick 4 * +
   ( type range pnac nsc nac address offset parent-mapping-address )
   \ get pnac
   5 pick
   \ read parent mapping
   (range-read-cells)
   ( type range pnac nsc nac address offset parent-mapping )
   + >r 3drop 3drop r> true
;

\ this word translates the given address starting from the node specified
\ in node; the word will return to the node it was started from
: translate-address  ( node address -- address )
   \ check for address type in "assigned-addresses"
   2dup 1 pci-address-type  ( node address type )
   dup -1 = IF
      \ not found in "assigned-addresses", check in "reg"
      drop 2dup 0 pci-address-type ( node address type )
   THEN
   rot parent BEGIN
      \ check if it is the root node
      dup parent 0=  IF  2drop EXIT  THEN
      ( address type parent )
      s" #address-cells" 2 pick get-property 2drop l@ >r        \ nac
      s" #size-cells" 2 pick get-property 2drop l@ >r           \ nsc
      s" #address-cells" 2 pick parent get-property 2drop l@ >r \ pnac
      -rot ( node address type )
      s" ranges" 4 pick get-property  IF
         3drop
         ABORT" no ranges property; not translatable"
      THEN
      r> r> r> 3 roll
      ( node address type ranges pnac nsc nac length )
      4 / >r 3dup + + >r 5 roll r> r> swap / 0 ?DO
         ( node type ranges pnac nsc nac address )
         6dup (map-one-range) IF
            nip leave
         THEN
         nip
         \ advance ranges
         4 roll
         ( node type pnac nsc nac address ranges )
         4 pick 4 pick 4 pick + + 4 * + 4 -roll
      LOOP
      >r 2drop 2drop r> ( node type address )
      swap rot parent ( address type node )
      dup 0=
   UNTIL
;

\ this words translates the given address starting from the current node
: translate-my-address  ( address -- address' )
   get-node swap translate-address
;
