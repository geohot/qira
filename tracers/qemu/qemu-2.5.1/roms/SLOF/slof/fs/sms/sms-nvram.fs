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

\ Initialize SMS NVRAM handling.

: sms-init-nvram ( -- )
   nvram-partition-type-sms get-nvram-partition IF
      cr ." Could not find SMS partition in NVRAM - "
      nvram-partition-type-sms s" SMS" d# 1024 new-nvram-partition
      ABORT" Failed to create SMS NVRAM partition"
      2dup erase-nvram-partition drop

      2dup s" lang"			  s" 1" internal-set-env drop

      2dup s" tftp-retries"		  s" 5" internal-set-env drop
      2dup s" tftp-blocksize"		s" 512" internal-set-env drop
      2dup s" bootp-retries"		s" 255" internal-set-env drop
      2dup s" client"	    s" 000.000.000.000" internal-set-env drop
      2dup s" server"       s" 000.000.000.000" internal-set-env drop
      2dup s" gateway"      s" 000.000.000.000" internal-set-env drop
      2dup s" netmask"      s" 255.255.255.000" internal-set-env drop
      2dup s" net-protocol"		  s" 0" internal-set-env drop
      2dup s" net-flags"		  s" 0" internal-set-env drop
      2dup s" net-device"		  s" 0" internal-set-env drop
      2dup s" net-client-name"		   s" " internal-set-env drop

      2dup s" scsi-spinup"		  s" 6" internal-set-env drop
      2dup s" scsi-id-0"		  s" 7" internal-set-env drop
      2dup s" scsi-id-1"		  s" 7" internal-set-env drop
      2dup s" scsi-id-2"		  s" 7" internal-set-env drop
      2dup s" scsi-id-3"		  s" 7" internal-set-env drop
      ." created" cr
   THEN
   s" sms-nvram-partition" $2constant
;

sms-init-nvram

: sms-add-env ( "name" "value" -- ) sms-nvram-partition 2rot 2rot internal-add-env drop ;
: sms-set-env ( "name" "value" -- ) sms-nvram-partition 2rot 2rot internal-set-env drop ;
: sms-get-env ( "name" -- "value" TRUE | FALSE) sms-nvram-partition 2swap internal-get-env ;

: sms-get-net-device ( -- n )	s" net-device" sms-get-env IF $dnumber IF 0 THEN ELSE 0 THEN ;
: sms-set-net-device ( n -- )	(.d) s" net-device" 2swap sms-set-env ;

: sms-get-net-flags ( -- n )	s" net-flags" sms-get-env IF $dnumber IF 0 THEN ELSE 0 THEN ;
: sms-set-net-flags ( n -- )	(.d) s" net-flags" 2swap sms-set-env ;

: sms-get-net-protocol ( -- n )	s" net-protocol" sms-get-env IF $dnumber IF 0 THEN ELSE 0 THEN ;
: sms-set-net-protocol ( n -- )	(.d) s" net-protocol" 2swap sms-set-env ;

: sms-get-lang ( -- n )	s" lang" sms-get-env IF $dnumber IF 1 THEN ELSE 1 THEN ;
: sms-set-lang ( n -- )	(.d) s" lang" 2swap sms-set-env ;

: sms-get-bootp-retries ( -- n ) s" bootp-retries" sms-get-env IF $dnumber IF 255 THEN ELSE 255 THEN ;
: sms-set-bootp-retries ( n -- ) (.d) s" bootp-retries" 2swap sms-set-env ;

: sms-get-tftp-retries ( -- n )	s" tftp-retries" sms-get-env IF $dnumber IF 5 THEN ELSE 5 THEN ;
: sms-set-tftp-retries ( n -- ) (.d) s" tftp-retries" 2swap sms-set-env ;

: sms-get-tftp-blocksize ( -- n ) s" tftp-blocksize" sms-get-env IF $dnumber IF 5 THEN ELSE 5 THEN ;
: sms-set-tftp-blocksize ( n -- ) (.d) s" tftp-blocksize" 2swap sms-set-env ;

: sms-get-client ( -- FALSE | n1 n2 n3 n4 TRUE ) s" client" sms-get-env IF (ipaddr) ELSE false THEN ;
: sms-set-client ( n1 n2 n3 n4 -- ) (ipformat) s" client" 2swap sms-set-env ;

: sms-get-server ( -- FALSE | n1 n2 n3 n4 TRUE ) s" server" sms-get-env IF (ipaddr) ELSE false THEN ;
: sms-set-server ( n1 n2 n3 n4 -- ) (ipformat) s" server" 2swap sms-set-env ;

: sms-get-gateway ( -- FALSE | n1 n2 n3 n4 TRUE ) s" gateway" sms-get-env IF (ipaddr) ELSE false THEN ;
: sms-set-gateway ( n1 n2 n3 n4 -- ) (ipformat) s" gateway" 2swap sms-set-env ;

: sms-get-subnet ( -- FALSE | n1 n2 n3 n4 TRUE ) s" netmask" sms-get-env IF (ipaddr) ELSE false THEN ;
: sms-set-subnet ( n1 n2 n3 n4 -- ) (ipformat) s" netmask" 2swap sms-set-env ;

: sms-get-client-name ( -- FALSE | addr len TRUE ) s" net-client-name" sms-get-env ;
: sms-set-client-name ( addr len -- ) s" net-client-name" 2swap sms-set-env ;

: sms-get-scsi-spinup ( -- n )	s" scsi-spinup" sms-get-env IF $dnumber IF 6 THEN ELSE 6 THEN ;
: sms-set-scsi-spinup ( n -- )	(.d) s" scsi-spinup" 2swap sms-set-env ;

: sms-get-scsi-id ( n -- id )	s" scsi-id-" rot (.) $cat sms-get-env IF $dnumber IF 6 THEN ELSE 6 THEN ;
: sms-set-scsi-id ( id n -- ) swap (.d) rot s" scsi-id-" rot (.) $cat sms-set-env ;


\ generates the boot-file part of the boot string

: sms-get-net-boot-file ( -- addr len )
   \ the format is
   \ :[bootp,]siaddr,filename,ciaddr,giaddr,bootp-retries,tftp-retries
   \ we choose dhcp as a default!
   s" net" sms-get-net-device (.) $cat
   s" :dhcp," $cat
   sms-get-server IF (ipformat) $cat THEN
   s" ," $cat
   sms-get-client-name IF $cat THEN
   s" ," $cat
   sms-get-client IF (ipformat) $cat THEN
   s" ," $cat
   sms-get-gateway IF (ipformat) $cat THEN
   s" ," $cat
   \ If the number of retries is 255 (max), assume default timeout (10min)
   sms-get-bootp-retries dup ff <> IF (.) $cat ELSE drop THEN
   s" ," $cat
   sms-get-tftp-retries (.) $cat
   \ now write the string to the boot path
   dup IF
      \ This could be considered a memory leak, but it is only
      \ executed once for booting so it is not a problem
      strdup ( s" :" 2swap $cat strdup )
   THEN
;

' sms-get-net-boot-file to furnish-boot-file

