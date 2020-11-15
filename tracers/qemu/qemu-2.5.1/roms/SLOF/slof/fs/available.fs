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

VARIABLE chosen-memory-ih 0 chosen-memory-ih !

\ +
\ Maintain "available" property.
\ Sun has a single memory node with "available" property
\ and separate memory controller nodes.
\ We corespond memory nodes with their respective memory controllers
\ and use /chosen/memory as default memory node to hold the "available" map
\ NOTE -> /chosen/memory is expected 2B initialized before using claim/release
\ +

: (chosen-memory-ph) ( -- phandle )
	chosen-memory-ih @ ?dup 0= IF
		s" memory" get-chosen IF
			decode-int nip nip dup chosen-memory-ih !
			ihandle>phandle
		ELSE 0 THEN
	ELSE ihandle>phandle THEN
;

: (set-available-prop) ( prop plen -- )
	s" available"
	(chosen-memory-ph) ?dup 0<> IF set-property ELSE
		cr ." Can't find chosen memory node - "
		." no available property created" cr
		2dup 2dup
	THEN
;

: update-available-property ( available-ptr -- )
	dup >r available>size@
	0= r@ available AVAILABLE-SIZE /available * + >= or IF
		available r> available - encode-bytes (set-available-prop)
	ELSE
		r> /available + RECURSE
	THEN
;

: update-available-property available update-available-property ;

\ \\\\\\\\\\\\\\ Exported Interface:
\ +
\ IEEE 1275 implementation:
\	claim
\ Claim the region with given start address and size (if align parameter is 0);
\ alternatively claim any region of given alignment
\ +
\ Throw an exception if failed
\ +
: claim ( [ addr ] len align -- base ) claim update-available-property ;

\ +
\ IEEE 1275 implementation:
\	release
\ Free the region with given start address and size
\ +
: release ( addr len -- ) release update-available-property ;

update-available-property

