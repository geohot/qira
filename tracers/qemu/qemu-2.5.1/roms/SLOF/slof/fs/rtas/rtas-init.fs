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

\ (rtas-size) determines the size required for RTAS.
\ It looks at the rtas binary in the flash and reads the rtas-size from
\ its header at offset 8.
: (rtas-size)  ( -- rtas-size )
   s" rtas" romfs-lookup dup 0=
   ABORT" romfs-lookup for rtas failed"
   drop 8 + @
;

(rtas-size) CONSTANT rtas-size

: instantiate-rtas ( adr -- entry )
    dup rtas-size erase
    s" rtas" romfs-lookup 0=
    ABORT" romfs-lookup for rtas failed"
    rtas-config swap start-rtas ;

here fff + fffffffffffff000 and here - allot
here rtas-size allot CONSTANT rtas-start-addr

rtas-start-addr instantiate-rtas CONSTANT rtas-entry-point

: drone-rtas
   rtas-start-addr
   dup rtas-size erase
   2000000 start-rtas to rtas-entry-point
;


\ ffffffffffffffff CONSTANT rtas-entry-point

\ rtas control block

STRUCT
	/l field rtas>token
	/l field rtas>nargs
	/l field rtas>nret
	/l field rtas>args0
        /l field rtas>args1
        /l field rtas>args2
        /l field rtas>args3
        /l field rtas>args4
        /l field rtas>args5
        /l field rtas>args6
        /l field rtas>args7
        /l C * field rtas>args
        /l field rtas>bla

CONSTANT /rtas-control-block

CREATE rtas-cb /rtas-control-block allot
rtas-cb  /rtas-control-block erase

\ call-c ( p0 p1 p2 entry -- ret )

: enter-rtas ( -- )
    rtas-cb rtas-start-addr 0 rtas-entry-point call-c drop ;


\ This is the structure of the RTAS function jump table in the C code:
STRUCT
	cell FIELD rtasfunctab>name
	cell FIELD rtasfunctab>func
	cell FIELD rtasfunctab>flags
CONSTANT rtasfunctab-size

\ Create RTAS token properties by analyzing the jump table in the C code:
: rtas-create-token-properties ( -- )
    rtas-start-addr 10 + @ rtas-start-addr +     \ Get pointer to jump table
    rtas-start-addr 18 + @ rtas-start-addr + l@  \ Get the number of entries
    0  DO
	dup rtasfunctab>func @ 0<>            \ function pointer must not be NULL
	over rtasfunctab>flags @ 1 and 0=     \ Check the only-internal flag
	and
	IF
	    i 1+ encode-int                   \ Create the token value
	    2 pick rtasfunctab>name @ zcount  \ Create the token name string
	    property                          \ Create the property
	THEN
	rtasfunctab-size +                    \ Proceed to the next entry
    LOOP
    drop
;

\ Get the RTAS token that corresponds to an RTAS property name:
: rtas-get-token ( str len -- token|0 )
    rtas-start-addr 10 + @ rtas-start-addr +     \ Get pointer to jump table
    rtas-start-addr 18 + @ rtas-start-addr + l@  \ Get the number of entries
    0  DO
	dup rtasfunctab>name @          \ Get pointer to function name
	dup 0<>                         \ function name must not be NULL
	over zcount 5 pick = nip and    \ Check if both strings have same length
	IF
	    3 pick 3 pick               \ Make a copy of the token name string
	    comp 0=
	    IF
		drop 2drop
		i 1+                    \ If the name matched, return the token
		UNLOOP EXIT
	    THEN
	ELSE
	    drop
	THEN
	rtasfunctab-size +              \ Proceed to the next entry
    LOOP
    drop
    ." RTAS token not found: " type cr
    0
;
