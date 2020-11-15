\ *****************************************************************************
\ * Copyright (c) 2004, 2011 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/

\ \\\\\\\\\\\\\\ Constants
500 CONSTANT AVAILABLE-SIZE
4000 CONSTANT MIN-RAM-RESERVE \ prevent from using first pages

: MIN-RAM-SIZE         \ Initially available memory size
   epapr-ima-size IF
      epapr-ima-size
   ELSE
      20000000         \ assumed minimal memory size
   THEN
;
MIN-RAM-SIZE CONSTANT MIN-RAM-SIZE

\ \\\\\\\\\\\\\\ Structures
\ +
\ The available element size depends strictly on the address/size
\ value formats and will be different for various device types
\ +
STRUCT
	cell field available>address
	cell field available>size
CONSTANT /available


\ \\\\\\\\\\\\\\ Global Data
CREATE available AVAILABLE-SIZE /available * allot available AVAILABLE-SIZE /available * erase
VARIABLE mem-pre-released 0 mem-pre-released !

\ \\\\\\\\\\\\\\ Structure/Implementation Dependent Methods
: available>size@	available>size @ ;
: available>address@	available>address @ ;
: available>size!	available>size ! ;
: available>address!	available>address ! ;

: available! ( addr size available-ptr -- )
	dup -rot available>size! available>address!
;

: available@ ( available-ptr -- addr size )
	dup available>address@ swap available>size@
;


\ \\\\\\\\\\\\\\ Implementation Independent Methods (Depend on Previous)
\ +
\ Warning: They are not yet really independent from available formatting
\ +

\ +
\ Find position in the "available" where given range exists or can be inserted,
\ return pointer and logical found/notfound value
\ If error, return NULL pointer in addition to notfound code
\ +
: (?available-segment<) ( start1 end1 start2 end2 -- true/false ) drop < nip ;

: (?available-segment>) ( start1 end1 start2 end2 -- true/false ) -rot 2drop > ;

\ start1 to end1 is the area that should be claimed
\ start2 to end2 is the available segment
\ return true if it can not be claimed, false if it can be claimed
: (?available-segment-#) ( start1 end1 start2 end2 -- true/false )
	2dup 5 roll -rot                ( e1 s2 e2 s1 s2 e2 )
	between >r between r> and not
;

: (find-available) ( addr addr+size-1 a-ptr a-size -- a-ptr' found )
	?dup 0= IF -rot 2drop false EXIT THEN	\ Not Found

	2dup 2/ dup >r /available * +
	( addr addr+size-1 a-ptr a-size a-ptr'  R: a-size' )
	dup available>size@ 0= IF 2drop r> RECURSE EXIT THEN

	( addr addr+size-1 a-ptr a-size a-ptr'  R: a-size' )
	dup >r available@
	( addr addr+size-1 a-ptr a-size addr' size'  R: a-size' a-ptr' )
	over + 1- 2>r 2swap
	( a-ptr a-size addr addr+size-1 )
	( R: a-size' a-ptr' addr' addr'+size'-1 )

	2dup 2r@ (?available-segment>) IF
		2swap 2r> 2drop r>
		/available + -rot r> - 1- nip RECURSE EXIT	\ Look Right
	THEN
	2dup 2r@ (?available-segment<) IF
		2swap 2r> 2drop r>
		2drop r> RECURSE EXIT	\ Look Left
	THEN
	2dup 2r@ (?available-segment-#) IF	\ Conflict - segments overlap
		2r> 2r> 3drop 3drop 2drop
		1212 throw
	THEN
	2r> 3drop 3drop r> r> drop	( a-ptr' -- )
	dup available>size@ 0<>		( a-ptr' found -- )
;

: (find-available) ( addr size -- seg-ptr found )
	over + 1- available AVAILABLE-SIZE ['] (find-available) catch IF
		2drop 2drop 0 false
	THEN
;


: dump-available ( available-ptr -- )
	cr
	dup available - /available / AVAILABLE-SIZE swap - 0 ?DO
		dup available@ ?dup 0= IF
			2drop UNLOOP EXIT
		THEN
		swap . . cr
		/available +
	LOOP
	dup
;

: .available available dump-available ;

\ +
\ release utils:
\ +

\ +
\ (drop-available) just blindly compresses space of available map
\ +
: (drop-available) ( available-ptr -- )
	dup available - /available /	\ current element index
	AVAILABLE-SIZE swap -		\ # of remaining elements

	( first nelements ) 1- 0 ?DO
		dup /available + dup available@

		( current next next>address next>size ) ?dup 0= IF
			2drop LEAVE \ NULL element - goto last copy
		THEN
		3 roll available!		( next )
	LOOP

	\ Last element : just zero it out
	0 0 rot available!
;

\ +
\ (stick-to-previous-available) merge the segment on stack
\ with the previous one, if possible, and modified segment parameters if merged
\ Return success code
\ +
: (stick-to-previous-available) ( addr size available-ptr -- naddr nsize nptr success )
	dup available = IF
		false EXIT		\ This was the first available segment
	THEN

	dup /available - dup available@
	+ 4 pick = IF
		nip	\ Drop available-ptr since we are going to previous one
		rot drop	\ Drop start addr, we take the previous one

		dup available@ 3 roll + rot true
		( prev-addr prev-size+size prev-ptr true )
	ELSE
		drop false
		( addr size available-ptr false )
	THEN
;

\ +
\ (insert-available) just blindly makes space for another element on given
\ position
\ +
\ insert-available should also check adjacent elements and merge if new
\ region is contiguos w. others
\ +
: (insert-available) ( available-ptr -- available-ptr )
	dup				\ current element
	dup available - /available /	\ current element index
	AVAILABLE-SIZE swap -		\ # of remaining elements

	dup 0<= 3 pick available>size@ 0= or IF
		\ End of "available" or came to an empty element - Exit
		drop drop EXIT
	THEN

	over available@ rot

	( first	first/=current/ first>address first>size nelements ) 1- 0 ?DO
		2>r
		( first current R: current>address current>size )

		/available + dup available@
		( first current+1/=next/ next>address next>size )
		( R: current>address current>size )

		2r> 4 pick available! dup 0= IF
			\ NULL element - last copy
			rot /available + available!
			UNLOOP EXIT
		THEN
	LOOP

	( first next/=last/ last[0]>address last[0]>size ) ?dup 0<> IF
		cr ." release error: available map overflow"
		cr ." Dumping available property"
		.available
		cr ." No space for one before last entry:" cr swap . .
		cr ." Dying ..." cr 123 throw
	THEN

	2drop
;

: insert-available ( addr size available-ptr -- addr size available-ptr )
	dup available>address@ 0<> IF
		\ Not empty :
		dup available>address@ rot dup -rot -

		( addr available-ptr size available>address@-size )

		3 pick = IF	\ if (available>address@ - size == addr)
			\ Merge w. next segment - no insert needed

			over available>size@ + swap
			( addr size+available>size@ available-ptr )

			(stick-to-previous-available) IF
				\ Merged w. prev & next one : discard extra seg
				dup /available + (drop-available)
			THEN
		ELSE
			\ shift the rest of "available" to make space

			swap (stick-to-previous-available)
			not IF (insert-available) THEN
		THEN
	ELSE
		(stick-to-previous-available) drop
	THEN
;

defer release

\ +
\ claim utils:
\ +
: drop-available ( addr size available-ptr -- addr )
	dup >r available@
	( req_addr req_size segment_addr segment_size	R: available-ptr )

	over 4 pick swap - ?dup 0<> IF
		\ Segment starts before requested address : free the head space
		dup 3 roll swap r> available! -

		( req_addr req_size segment_size-segment_addr+req_addr )
		over - ?dup 0= IF
			\ That's it - remainder of segment is what we claim
			drop
		ELSE
			\ Both head and tail of segment remain unclaimed :
			\ need an extra available element
			swap 2 pick + swap release
		THEN
	ELSE
		nip ( req_addr req_size segment_size )
		over - ?dup 0= IF
			\ Exact match : drop the whole available segment
			drop r> (drop-available)
		ELSE
			\ We claimed the head, need to leave the tail available
			-rot over + rot r> available!
		THEN
	THEN
	( base	R: -- )
;

: pwr2roundup ( value -- pwr2value )
	dup CASE
		0 OF EXIT ENDOF
		1 OF EXIT ENDOF
	ENDCASE
	dup 1 DO drop i dup +LOOP
	dup +
;

: (claim-best-fit) ( len align -- len base )
	pwr2roundup 1- -1 -1
	( len align-1 best-fit-residue/=-1/ best-fit-base/=-1/ )

	available AVAILABLE-SIZE /available * + available DO
		i		\ Must be saved now, before we use Return stack
		-rot >r >r swap >r

		( len i		R: best-fit-base best-fit-residue align-1 )

		available@ ?dup 0= IF drop r> r> r> LEAVE THEN		\ EOL

		2 pick - dup 0< IF
			2drop			\ Can't Fit: Too Small
		ELSE
			dup 2 pick r@ and - 0< IF
				2drop		\ Can't Fit When Aligned
			ELSE
				( len i>address i>size-len )
				( R: best-fit-base best-fit-residue align-1 )
				r> -rot dup r@ U< IF
					\ Best Fit so far: drop the old one
					2r> 2drop

					( len align-1 nu-base nu-residue   R: )
					\ Now align new base and push to R:
					swap 2 pick + 2 pick invert and >r >r >r
				ELSE
					2drop >r
				THEN
			THEN
		THEN
		r> r> r>
	/available +LOOP

	-rot 2drop	( len best-fit-base/or -1 if none found/ )
;

: (adjust-release0) ( 0 size -- addr' size' )
	\ segment 0 already pre-relased in early phase: adjust
	2dup MIN-RAM-SIZE dup 3 roll + -rot -
	dup 0< IF 2drop ELSE
		2swap 2drop 0 mem-pre-released !
	THEN
;


\ \\\\\\\\\\\\\\ Exported Interface:
\ +
\ IEEE 1275 implementation:
\ 	claim
\ Claim the region with given start address and size (if align parameter is 0);
\ alternatively claim any region of given alignment
\ +
\ Throw an exception if failed
\ +
: claim ( [ addr ] len align -- base )
	?dup 0<> IF
		(claim-best-fit) dup -1 = IF
			2drop cr ." claim error : aligned allocation failed" cr
			." available:" cr .available
			321 throw EXIT
		THEN
		swap
	THEN

	2dup (find-available) not IF
		drop
\ 		cr ." claim error : requested " . ." bytes of memory at " .
\ 		." not available" cr
\ 		." available:" cr .available
		2drop
		321 throw EXIT
	THEN
	( req_addr req_size available-ptr ) drop-available

	( req_addr )
;


\ +
\ IEEE 1275 implementation:
\ 	release
\ Free the region with given start address and size
\ +
: .release ( addr len -- )
	over 0= mem-pre-released @ and IF (adjust-release0) THEN

	2dup (find-available) IF
		drop swap
		cr ." release error: region " . ." , " . ." already released" cr
	ELSE
		?dup 0= IF
			swap 
			cr ." release error: Bad/conflicting region " . ." , " .
			." or available list full " cr
		ELSE
			( addr size available-ptr ) insert-available

			\ NOTE: insert did not change the stack layout
			\ 	but it may have changed any of the three values
			\ 	in order to implement merge of free regions
			\ 	We do not interpret these values any more
			\ 	just blindly copy it in

			( addr size available-ptr ) available!
		THEN
	THEN
;

' .release to release


\ pre-release minimal memory size
0 MIN-RAM-SIZE release 1 mem-pre-released !

\ claim first pages used for PPC exception vectors
0 MIN-RAM-RESERVE 0 ' claim CATCH IF ." claim failed!" cr 2drop THEN drop

\ claim region used by firmware (assume 31 MiB size right now)
paflof-start ffff not and 1f00000 0 ' claim CATCH IF
   ." claim failed!" cr 2drop
THEN drop
