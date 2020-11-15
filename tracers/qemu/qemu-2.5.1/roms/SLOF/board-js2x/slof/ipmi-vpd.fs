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

: vpd-read-bootlist  ( -- )
   837 4 vpd-bootlist rtas-read-vpd IF vpd-bootlist 4 erase THEN
;

: vpd-write-bootlist  ( offset len data -- )
   837 4 vpd-bootlist rtas-write-vpd
;

: .vpd-machine-type
	e 7 vpd-cb rtas-read-vpd drop
	0 vpd-cb 7 + c!
	vpd-cb zcount type
;

: .vpd-machine-serial
	15 7 vpd-cb rtas-read-vpd drop
	0 vpd-cb 7 + c!
	vpd-cb zcount type
;

: .vpd-card-serial
	54 6 vpd-cb rtas-read-vpd drop
	0 vpd-cb 6 + c!
	vpd-cb zcount type
;
: .vpd-cardprefix-serial
	5a 6 vpd-cb rtas-read-vpd drop
	0 vpd-cb 6 + c!
	vpd-cb zcount type
;

: .vpd-hw-revision
	65 1 vpd-cb rtas-read-vpd drop
	vpd-cb c@ .
;

: .vpd-part-number
	3c c vpd-cb rtas-read-vpd drop
	vpd-cb c type
;

: .vpd-fru-number
	48 c vpd-cb rtas-read-vpd drop
	vpd-cb c type
;

: .vpd-manufacturer-date
	6b 4 vpd-cb rtas-read-vpd drop
	0 vpd-cb 4 + c!
	vpd-cb zcount type
;

: .vpd-uuid
	9f 10 vpd-cb rtas-read-vpd drop
	10 0 do i vpd-cb + c@ 2 0.r loop
;

: vpd-read-model  ( -- addr len )
   60 4 vpd-cb rtas-read-vpd drop vpd-cb 4 -leading s" ," $cat 
   e 7 vpd-cb rtas-read-vpd drop vpd-cb 4 $cat s" -" $cat vpd-cb 4 + 3 $cat
;

: .vpd
	." ===================== VPD =====================" 
	cr ." Machine Type        : " .vpd-machine-type
	cr ." Machine Serial No.  : " .vpd-machine-serial
	cr ." Hardware Revision   : " .vpd-hw-revision	
	cr ." Manuf. Date         : " .vpd-manufacturer-date
	cr ." Part Number         : " .vpd-part-number
	cr ." FRU Number          : " .vpd-fru-number
	cr ." FRU Serial No.      : " .vpd-cardprefix-serial .vpd-card-serial
	cr ." UUID                : " .vpd-uuid
;

: vpd-write-revision-and-build-id  ( -- )
   406 24 vpd-cb rtas-read-vpd drop 0
   vpd-cb 1a + zcount bdate2human drop a string=ci 0=
   IF  bdate2human drop a vpd-cb 1a + zplace drop 1  THEN
   vpd-cb zcount slof-revision string=ci 0=
   IF  slof-revision vpd-cb zplace drop 1  THEN
   vpd-cb 4 + zcount slof-build-id string=ci 0=
   IF  slof-build-id vpd-cb 4 + rzplace drop 1  THEN
   1 =  IF  406 24 vpd-cb rtas-write-vpd drop  THEN
;

vpd-write-revision-and-build-id
