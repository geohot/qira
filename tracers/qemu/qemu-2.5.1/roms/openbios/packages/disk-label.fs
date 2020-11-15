\ tag: Utility functions
\ 
\ deblocker / filesystem support
\ 
\ Copyright (C) 2003, 2004 Samuel Rydh
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

dev /packages

\ -------------------------------------------------------------
\ /packages/disk-label (partition handling)
\ -------------------------------------------------------------

[IFDEF] CONFIG_DISK_LABEL
  
new-device
  " disk-label" device-name
  external

  variable part-handlers      \ list with (probe-xt, phandle) elements
  variable fs-handlers        \ list with (fs-probe-xt, phandle) elements
  
  : find-part-handler ( block0 -- phandle | 0 )
    >r part-handlers
    begin list-get while
      ( nextlist dictptr )
      r@ over @ execute if
        ( nextlist dictptr )
        na1+ @ r> rot 2drop exit
      then
      drop
    repeat
    r> drop 0
  ;

  : find-filesystem ( offs.d ih -- ph | 0 )
    >r fs-handlers	( offs.d listhead )
    begin list-get while
      2over	( offs.d nextlist dictptr offs.d )
      r@ 	( offs.d nextlist dictptr offs.d ih )
	3 pick	( offs.d nextlist dictptr offs.d ih dictptr )
 	@	( offs.d nextlist dictptr offs.d ih probe-xt )
	execute ( offs.d nextlist dictptr flag? )
	if
        	( offs.d nextlist dictptr )
        	na1+	( offs.d nextlist dictptr+1 ) 
		@ 	( offs.d nextlist phandle )
		r>	( offs.d nextlist phandle ih )
		rot	( offs.d phandle ih nextlist )
		2drop	( offs.d phandle )
 		-rot	( phandle offs.d )
		2drop	( phandle )
		exit
      	then
      drop	( offs.d nextlist )
    repeat
    2drop	( offs.d )
    r> drop 0
  ;


  : register-part-handler ( handler-ph -- )
    dup " probe" rot find-method
    0= abort" Missing probe method!"
    ( phandle probe-xt )
    part-handlers list-add , ,
  ;

  : register-fs-handler ( handler-ph -- )
    dup " probe" rot find-method
    0= abort" Missing probe method!"
    ( phandle probe-xt )
    fs-handlers list-add , ,
  ;
finish-device

\ ---------------------------------------------------------------------------
\ methods to register partion and filesystem packages used by disk-label
\ ---------------------------------------------------------------------------

device-end
: register-partition-package ( -- )
  " register-part-handler" " disk-label" $find-package-method ?dup if
    active-package swap execute
  else
    ." [disk-label] internal error" cr
  then
;

: register-fs-package ( -- )
  " register-fs-handler" " disk-label" $find-package-method ?dup if  
    active-package swap execute
  else
    ." [misc-files] internal error" cr
  then
;

[THEN]
device-end
