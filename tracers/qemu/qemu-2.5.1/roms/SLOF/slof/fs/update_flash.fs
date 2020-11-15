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

\ Set by update-flash -f to true, preventing update-flash -c
false value flash-new

: update-flash-help ( -- )
   cr ." update-flash tool to flash host FW " cr
   ."              -f <filename>      : Flash from file (e.g. net:\boot_rom.bin)" cr
   ."              -l                 : Flash from load-base" cr
   ."              -d                 : Flash from old load base (used by drone)" cr
   ."              -c                 : Flash from temp to perm" cr
   ."              -r                 : Flash from perm to temp" cr
;

: flash-read-temp ( -- success? )
   get-flashside 1 = IF flash-addr get-load-base over flash-image-size rmove true
   ELSE
      false
   THEN
;

: flash-read-perm ( -- success? )
   get-flashside 0= IF
      flash-addr get-load-base over flash-image-size rmove true
   ELSE
      false
   THEN
;

: flash-switch-side ( side -- success? )
   set-flashside 0<> IF
      s" Cannot change flashside" type cr false
   ELSE
      true
   THEN
;

: flash-ensure-temp ( -- success? )
   get-flashside 0= IF
      cr ." Cannot flash perm! Switching to temp side!"
      1 flash-switch-side
   ELSE
      true
   THEN
;

\ update-flash -f <filename>
\              -l
\              -c
\              -r

: update-flash ( "text" )
   get-flashside >r                              \ Save old flashside
   parse-word                      ( str len )   \ Parse first string
   drop dup c@                     ( str first-char )
   [char] - <> IF
      update-flash-help r> 2drop EXIT
   THEN

   1+ c@                           ( second-char )
   CASE
      [char] f OF
         parse-word cr s" do-load" evaluate
         flash-ensure-temp TO flash-new
      ENDOF
      [char] l OF
         flash-ensure-temp
      ENDOF
      [char] d OF
         flash-load-base get-load-base 200000 move
         flash-ensure-temp
      ENDOF
      [char] c OF
         flash-read-temp 0= flash-new or IF
            ." Cannot commit temp, need to boot on temp first " cr false
         ELSE
            0 flash-switch-side
         THEN
      ENDOF
      [char] r OF
         flash-read-perm 0= IF
         ." Cannot commit perm, need to boot on perm first " cr false
         ELSE
         1 flash-switch-side
         THEN
      ENDOF
      dup      OF
         false
      ENDOF
   ENDCASE

   ( true| false )

   0= IF
      update-flash-help r> drop EXIT
   THEN

   get-load-base flash-write 0= IF ." Flash write failed !! " cr THEN
   r> set-flashside drop                           \ Restore old flashside
;
