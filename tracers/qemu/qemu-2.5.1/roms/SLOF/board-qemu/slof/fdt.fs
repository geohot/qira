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

0 VALUE fdt-debug
TRUE VALUE fdt-cas-fix?

\ Bail out if no fdt
fdt-start 0 = IF -1 throw THEN

struct
  4 field >fdth_magic
  4 field >fdth_tsize
  4 field >fdth_struct_off
  4 field >fdth_string_off
  4 field >fdth_rsvmap_off
  4 field >fdth_version
  4 field >fdth_compat_vers
  4 field >fdth_boot_cpu
  4 field >fdth_string_size
  4 field >fdth_struct_size
drop

h# d00dfeed constant OF_DT_HEADER
h#        1 constant OF_DT_BEGIN_NODE
h#        2 constant OF_DT_END_NODE
h#        3 constant OF_DT_PROP
h#        4 constant OF_DT_NOP
h#        9 constant OF_DT_END

\ Create some variables early
0 value fdt-start-addr
0 value fdt-struct
0 value fdt-strings

: fdt-init ( fdt-start -- )
    dup to fdt-start-addr
    dup dup >fdth_struct_off l@ + to fdt-struct
    dup dup >fdth_string_off l@ + to fdt-strings
    drop
;
fdt-start fdt-init

\ Dump fdt header for all to see and check FDT validity
: fdt-check-header ( -- )
    fdt-start-addr dup 0 = IF
        ." No flat device tree !" cr drop -1 throw EXIT THEN
    hex
    fdt-debug IF
        ." Flat device tree header at 0x" dup . s" :" type cr
        ."  magic            : 0x" dup >fdth_magic l@ . cr
        ."  total size       : 0x" dup >fdth_tsize l@ . cr
        ."  offset to struct : 0x" dup >fdth_struct_off l@ . cr
        ."  offset to strings: 0x" dup >fdth_string_off l@ . cr
        ."  offset to rsvmap : 0x" dup >fdth_rsvmap_off l@ . cr
        ."  version          : " dup >fdth_version l@ decimal . hex cr
        ."  last compat vers : " dup >fdth_compat_vers l@ decimal . hex cr
        dup >fdth_version l@ 2 >= IF
            ."  boot CPU         : 0x" dup >fdth_boot_cpu l@ . cr
        THEN
        dup >fdth_version l@ 3 >= IF
            ."  strings size     : 0x" dup >fdth_string_size l@ . cr
        THEN
        dup >fdth_version l@ 17 >= IF
            ."  struct size      : 0x" dup >fdth_struct_size l@ . cr
        THEN
    THEN
    dup >fdth_magic l@ OF_DT_HEADER <> IF
        ." Flat device tree has incorrect magic value !" cr
	drop -1 throw EXIT
    THEN
    dup >fdth_version l@ 10 < IF
        ." Flat device tree has usupported version !" cr
	drop -1 throw EXIT
    THEN

    drop
;
fdt-check-header

\ Fetch next tag, skip nops and increment address
: fdt-next-tag ( addr -- nextaddr tag )
  0	       	      	 	( dummy tag on stack for loop )
  BEGIN
    drop			( drop previous tag )
    dup l@			( read new tag )
    swap 4 + swap		( increment addr )
  dup OF_DT_NOP <> UNTIL 	( loop until not nop )
;

\ Parse unit name and advance addr
: fdt-fetch-unit ( addr -- addr $name )
  dup from-cstring	       \  get string size
  2dup + 1 + 3 + fffffffc and -rot
;

\ Update unit with information from the reg property...
\ ... this is required for the PCI nodes for example.
: fdt-reg-unit ( prop-addr prop-len -- )
      decode-phys               ( prop-addr' prop-len' phys.lo ... phys.hi )
      set-unit                  ( prop-addr' prop-len' )
      2drop
;

\ Lookup a string by index
: fdt-fetch-string ( index -- str-addr str-len )  
  fdt-strings + dup from-cstring
;

: fdt-create-dec  s" decode-unit" $CREATE , DOES> @ hex64-decode-unit ;
: fdt-create-enc  s" encode-unit" $CREATE , DOES> @ hex64-encode-unit ;

\ Check whether array contains an zero-terminated ASCII string:
: fdt-prop-is-string?  ( addr len -- string? )
   dup 1 < IF 2drop FALSE EXIT THEN                \ Check for valid length
   1-
   2dup + c@ 0<> IF 2drop FALSE EXIT THEN          \ Check zero-termination
   test-string
;

\ Encode fdt property to OF property
: fdt-encode-prop  ( addr len -- )
   2dup fdt-prop-is-string? IF
      1- encode-string
   ELSE
      encode-bytes
   THEN
;

\ Method to unflatten a node
: fdt-unflatten-node ( start -- end )
  \ this can and will recurse
  recursive

  \ Get & check first tag of node ( addr -- addr)
  fdt-next-tag dup OF_DT_BEGIN_NODE <> IF
    s" Weird tag 0x" type . " at start of node" type cr
    -1 throw
  THEN drop

  new-device

  \ Parse name, split unit address
  fdt-fetch-unit
  dup 0 = IF drop drop " /" THEN
  40 left-parse-string
  \ Set name
  device-name

  \ Set preliminary unit address - might get overwritten by reg property
  dup IF
     " #address-cells" get-parent get-package-property IF
        2drop
     ELSE
        decode-int nip nip
	hex-decode-unit
	set-unit
     THEN
  ELSE 2drop THEN

  \ Iterate sub tags
  BEGIN
    fdt-next-tag dup OF_DT_END_NODE <>
  WHILE
    dup OF_DT_PROP = IF
      \ Found property
      drop dup			( drop tag, dup addr     : a1 a1 )
      dup l@ dup rot 4 +	( fetch size, stack is   : a1 s s a2)
      dup l@ swap 4 +		( fetch nameid, stack is : a1 s s i a3 )
      rot			( we now have: a1 s i a3 s )
      fdt-encode-prop rot	( a1 s pa ps i)
      fdt-fetch-string		( a1 s pa ps na ns )
      2dup s" reg" str= IF
          2swap 2dup fdt-reg-unit 2swap
      THEN
      property
      + 8 + 3 + fffffffc and
    ELSE dup OF_DT_BEGIN_NODE = IF
      drop			( drop tag )
      4 -
      fdt-unflatten-node
    ELSE
      drop -1 throw
    THEN THEN
  REPEAT drop \ drop tag

  \ Create encode/decode unit
  " #address-cells" get-node get-package-property IF ELSE
    decode-int dup fdt-create-dec fdt-create-enc 2drop
  THEN

  finish-device  
;

\ Start unflattening
: fdt-unflatten-tree
    fdt-debug IF
        ." Unflattening device tree..." cr THEN
    fdt-struct fdt-unflatten-node drop
    fdt-debug IF
        ." Done !" cr THEN
;
fdt-unflatten-tree

\ Find memory size
: fdt-parse-memory
    \ XXX FIXME Handle more than one memory node, and deal
    \     with RMA vs. full access
    " /memory@0" find-device
    " reg" get-node get-package-property IF throw -1 THEN

    \ XXX FIXME Assume one entry only in "reg" property for now
    decode-phys 2drop decode-phys
    my-#address-cells 1 > IF 20 << or THEN
    
    fdt-debug IF
        dup ." Memory size: " . cr
    THEN
    \ claim.fs already released the memory between 0 and MIN-RAM-SIZE,
    \ so we've got only to release the remaining memory now:
    MIN-RAM-SIZE swap MIN-RAM-SIZE - release
    2drop device-end
;
fdt-parse-memory


\ Claim fdt memory and reserve map
: fdt-claim-reserve
    fdt-start-addr
    dup dup >fdth_tsize l@ 0 claim drop
    dup >fdth_rsvmap_off l@ +
    BEGIN
        dup dup x@ swap 8 + x@
	dup 0 <>
    WHILE
	fdt-debug IF
	    2dup swap ." Reserve map entry: " . ." : " . cr
	THEN
	0 claim drop
	10 +
    REPEAT drop drop drop
;
fdt-claim-reserve 


\ The following functions are use to replace the FDT phandle and
\ linux,phandle properties with our own OF1275 phandles...

\ This is used to check whether we successfully replaced a phandle value
0 VALUE (fdt-phandle-replaced)

\ Replace phandle value in "interrupt-map" property
: fdt-replace-interrupt-map  ( old new prop-addr prop-len -- old new )
   BEGIN
      dup                    ( old new prop-addr prop-len prop-len )
   WHILE
      \ This is a little bit ugly ... we're accessing the property at
      \ hard-coded offsets instead of analyzing it completely...
      swap dup 10 +          ( old new prop-len prop-addr prop-addr+10 )
      dup l@ 5 pick = IF
          \ it matches the old phandle value!
          3 pick swap l!
          TRUE TO (fdt-phandle-replaced)
      ELSE
          drop
      THEN
      ( old new prop-len prop-addr )
      1c + swap 1c -
      ( old new new-prop-addr new-prop-len )
   REPEAT
   2drop
;

\ Replace one FDT phandle "old" with a OF1275 phandle "new" in the
\ whole tree:
: fdt-replace-all-phandles ( old new node -- )
   \ ." Replacing in " dup node>path type cr
   >r
   s" interrupt-map" r@ get-property 0= IF
      ( old new prop-addr prop-len  R: node )
      fdt-replace-interrupt-map
   THEN
   s" interrupt-parent" r@ get-property 0= IF
      ( old new prop-addr prop-len  R: node )
      decode-int -rot 2drop                  ( old new val  R: node )
      2 pick = IF                            ( old new      R: node )
         dup encode-int s" interrupt-parent" r@ set-property
         TRUE TO (fdt-phandle-replaced)
      THEN
   THEN
   \ ... add more properties that have to be fixed here ...
   r>
   \ Now recurse over all child nodes:       ( old new node )
   child BEGIN
      dup
   WHILE
      3dup RECURSE
      PEER
   REPEAT
   3drop
;

\ Check whether a node has "phandle" or "linux,phandle" properties
\ and replace them:
: fdt-fix-node-phandle  ( node -- )
   >r
   FALSE TO (fdt-phandle-replaced)
   s" phandle" r@ get-property 0= IF
      decode-int                       ( p-addr2 p-len2 val )
      \ ." found phandle: " dup . cr
      r@ s" /" find-node               ( p-addr2 p-len2 val node root )  
      fdt-replace-all-phandles         ( p-addr2 p-len2 )
      2drop
      (fdt-phandle-replaced) IF
         r@ set-node
         s" phandle" delete-property
         s" linux,phandle" delete-property
      ELSE
         diagnostic-mode? IF
            cr ." Warning: Did not replace phandle in " r@ node>path type cr
         THEN
      THEN
   THEN
   r> drop
;

\ Recursively walk through all nodes to fix their phandles:
: fdt-fix-phandles  ( node -- )
   \ ." fixing phandles of " dup node>path type cr
   dup fdt-fix-node-phandle
   child BEGIN
      dup
   WHILE
      dup RECURSE
      PEER
   REPEAT
   drop
   device-end
;

: fdt-create-cas-node ( name  -- )
    2dup
    2dup " memory@" find-substr 0 = IF
	fdt-debug IF ." Creating memory@ " cr THEN
	new-device
	2dup " @" find-substr nip device-name       \ Parse the node name
	2dup
	2dup " @" find-substr rot over + 1 + -rot - 1 - \ Jump to addr afte "@"
	parse-2int nip xlsplit set-unit                 \ Parse and set unit
	finish-device
    ELSE
	2dup " ibm,dynamic-reconfiguration-memory" find-substr 0 = IF
	    fdt-debug IF  ." Creating ibm,dynamic-reconfiguration-memory " cr THEN
	    new-device
	    device-name
	    finish-device
	ELSE
	    2drop 2drop
	    false to fdt-cas-fix?
	    ." Node not supported " cr
	    EXIT
	THEN
    THEN

    find-node ?dup 0 <> IF set-node THEN
;

: fdt-fix-cas-node ( start -- end )
    recursive
    fdt-next-tag dup OF_DT_BEGIN_NODE <> IF
	." Error " cr
	false to fdt-cas-fix?
	EXIT
    THEN drop
    fdt-fetch-unit
    dup 0 = IF drop drop " /" THEN
    40 left-parse-string
    2swap ?dup 0 <> IF
	nip
	1 + + \ Add the string len +@
    ELSE
	drop
    THEN
    fdt-debug IF ." Setting node: " 2dup type cr THEN
    2dup find-node ?dup 0 <> IF
	set-node 2drop
    ELSE
	fdt-debug IF ." Node not found, creating " 2dup type cr THEN
	fdt-create-cas-node
    THEN
    fdt-debug IF ." Current  now: " pwd cr THEN
    BEGIN
	fdt-next-tag dup OF_DT_END_NODE <>
    WHILE
	dup OF_DT_PROP = IF
	    fdt-debug IF ." Found property " cr THEN
	    drop dup		( drop tag, dup addr     : a1 a1 )
	    dup l@ dup rot 4 +	( fetch size, stack is   : a1 s s a2)
	    dup l@ swap 4 +	( fetch nameid, stack is : a1 s s i a3 )
	    rot			( we now have: a1 s i a3 s )
	    fdt-encode-prop rot	( a1 s pa ps i)
	    fdt-fetch-string		( a1 s pa ps na ns )
	    property
	    fdt-debug IF ." Setting property done " cr THEN
	    + 8 + 3 + fffffffc and
	ELSE dup OF_DT_BEGIN_NODE = IF
		drop			( drop tag )
		4 -
		fdt-fix-cas-node
		get-parent set-node
		fdt-debug IF ." Returning back " pwd cr THEN
	    ELSE
		." Error " cr
		drop
		false to fdt-cas-fix?
		EXIT
	    THEN
	THEN
    REPEAT
    drop \ drop tag
;

: fdt-fix-cas-success
    fdt-cas-fix?
;

s" /" find-node fdt-fix-phandles
