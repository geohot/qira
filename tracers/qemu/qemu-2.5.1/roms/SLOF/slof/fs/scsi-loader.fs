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

\ **************************************
\ Last change: MiR 13.11.2007 10:55:57
\ **************************************

: .ansi-attr-off 1b emit ." [0m"  ;    \ ESC Sequence: all terminal attributes off
: .ansi-blue     1b emit ." [34m" ;    \ ESC Sequence: foreground-color = blue
: .ansi-green    1b emit ." [32m" ;    \ ESC Sequence: foreground-color = green
: .ansi-red      1b emit ." [31m" ;    \ ESC Sequence: foreground-color = green
: .ansi-bold     1b emit ." [1m"  ;    \ ESC Sequence: foreground-color bold

false VALUE scsi-supp-present?

: scsi-xt-err ." SCSI-ERROR (Intern) " ;
' scsi-xt-err VALUE scsi-open-xt        \ preset with an invalid token

\ *************************************
\ utility to show all active word-lists
\ *************************************
: .wordlists      ( -- )
   .ansi-red
   get-order      ( -- wid1 .. widn n )
   dup space 28 emit .d ." word lists : "
   0 DO
      . 08 emit 2c emit
   LOOP
   08 emit                 \ 'bs'
   29 emit                 \ ')'
   cr space 28 emit
   ." Context: " context dup .
   @ 5b emit . 8 emit 5d emit
   space
   ." / Current: " current .
   .ansi-attr-off
   cr
;

\ *************************************
\ utility to show first word-lists
\ *************************************
: .context  ( num -- )
   .ansi-red
    space
   5b emit
   23 emit . 3a emit
   context @
   . 8 emit 5d emit space
   .ansi-attr-off
;

\ ****************************************************************************
\ open scsi-support by adding a new word list on top of search path
\ first check if scsi-support.fs must be included (first call)
\ when open use execution pointer to access version in new word list
\ ****************************************************************************
: scsi-open  ( -- )
   scsi-supp-present? NOT
   IF
      s" scsi-support.fs" included  ( xt-open )
      to scsi-open-xt               (  )
      true to scsi-supp-present?
   THEN
   scsi-open-xt execute
;


