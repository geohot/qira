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

4 CONSTANT vpd-bootlist-size

\ Bootable devices
00 CONSTANT FLOPPY
01 CONSTANT USB
02 CONSTANT SAS
03 CONSTANT SATA
04 CONSTANT ISCSI
05 CONSTANT ISCSICRITICAL
06 CONSTANT NET
07 CONSTANT NOTSPECIFIED
08 CONSTANT HDD0
09 CONSTANT HDD1
0a CONSTANT HDD2
0b CONSTANT HDD3
0c CONSTANT CDROM
0e CONSTANT HDD4
10 CONSTANT SCSI

: check-bootlist ( -- true | false )
   vpd-bootlist l@
   dup 0= IF
      ( bootlist == 0 means that probably nothing from vpd has been received )
      s" Boot list could not be read from VPD" log-string cr
      s" Boot watchdog has been rearmed" log-string cr
      2 set-watchdog
      EXIT
   THEN

   FFFFFFFF = IF
      ( bootlist all FFs means that the vpd has no useful information )
      .banner
      -6b boot-exception-handler
      \ The next message is duplicate, but sent w. log-string
      s" Boot list successfully read from VPD but no useful information received" log-string cr
      s" Please specify the boot device in the management module" log-string cr
      s" Specified Boot Sequence not valid" mm-log-warning
      false
      EXIT
   THEN

   true
;

\ the following words are necessary for vpd-boot-import
defer set-boot-device
defer add-boot-device

\ select-install? is a flag which is used in the SMS panel #20
\ "Select/Install Boot Devices".
\ This panel can be used to temporarily override the boot device.
false VALUE select-install?

\ select/install-path stores string address and string length of the
\ device node chosen in the SMS panel #20 "Select/Install Boot Devices"
\ This device node is prepended to the boot path if select-install? is
\ true.
CREATE select/install-path 2 cells allot

\ Import boot device list from VPD
\ If none, keep the existing list in NVRAM
\ This word can be used to overwrite read-bootlist if wanted

: vpd-boot-import  ( -- )
   0 0 set-boot-device

   select-install? IF
      select/install-path 2@ add-boot-device
   THEN

   vpd-read-bootlist
   check-bootlist  IF
      4 0  DO  vpd-bootlist i + c@
         CASE
            6  OF  \ cr s" 2B Booting from Network" log-string cr
               furnish-boot-file strdup add-boot-device
	    ENDOF

            HDD0  OF  \ cr s" 2B Booting from hdd0" log-string cr
               s" disk hdd0" add-boot-device ENDOF

            HDD1  OF  \ cr s" 2B Booting from hdd1" log-string cr
               s" hdd1" add-boot-device ENDOF

            HDD2  OF  \ cr s" 2B Booting from hdd2" log-string cr
               s" hdd2" add-boot-device ENDOF

            HDD3  OF  \ cr s" 2B Booting from hdd3" log-string cr
               s" hdd3" add-boot-device ENDOF

            CDROM OF  \ cr s" 2B Booting from CDROM" log-string cr
               s" cdrom" add-boot-device ENDOF

            HDD4  OF  \ cr s" 2B Booting from hdd4" log-string cr
               s" hdd4" add-boot-device ENDOF

            F  OF  \ cr s" 2B Booting from SAS - w. Timeout" log-string cr
		s" sas" add-boot-device ENDOF

            SCSI  OF  \ cr s" 2B Booting from SAS - Continuous Retry" log-string cr
		s" sas" add-boot-device ENDOF

         ENDCASE
      LOOP
      bootdevice 2@ nip
      IF 0
      ELSE
	 \ Check for all no device -> use boot-device  
	 vpd-bootlist l@ 07070707 = IF 0 ELSE -6b THEN 
      THEN
   ELSE -6a THEN
   boot-exception-handler
;

: vpd-bootlist-restore-default  ( -- )
   NOTSPECIFIED vpd-bootlist 0 + c!
   NOTSPECIFIED vpd-bootlist 1 + c!
   NOTSPECIFIED vpd-bootlist 2 + c!
   HDD0 vpd-bootlist 3 + c!
   vpd-write-bootlist
;

