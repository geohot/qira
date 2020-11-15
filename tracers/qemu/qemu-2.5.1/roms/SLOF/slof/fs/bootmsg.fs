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
create debugstr 255 allot
0 VALUE debuglen
\ tbl@ d# 1000 * 196e6aa / VALUE TIME1
\ 0 VALUE TIME2

\ Usage: 42 cp
: cp ( checkpoint -- )
  \ cr depth 2 0.r s"  : " type .s cr  \ DEBUG
  \ cr ." time: " tbl@ d# 1000 * 196e6aa / dup TIME1 - dup . cr TIME2 + TO TIME2 TO TIME1
  bootmsg-cp ;

: (warning) ( id level ptr len -- )
  dup TO debuglen
  debugstr swap move           \ copy into buffer
  0 debuglen debugstr + c!     \ terminate '\0'
  debugstr bootmsg-warning
;

\ Usage: 42 0 warning" warning-txt"
: warning" ( id level [text<">] -- )
  postpone s" state @
  IF
    ['] (warning) compile,
  ELSE
    (warning)
  THEN
; immediate

: (debug-cp) ( id level ptr len -- )
  dup TO debuglen
  debugstr swap move           \ copy into buffer
  0 debuglen debugstr + c!     \ terminate '\0'
  debugstr bootmsg-debugcp
;

\ Usage: 42 0 debug-cp" debug-cp-txt"
: debug-cp" ( id level [text<">] -- )
  postpone s" state @
  IF
    ['] (debug-cp) compile,
  ELSE
    (debug-cp)
  THEN
; immediate

: (error) ( id ptr len -- )
  dup TO debuglen
  debugstr swap move           \ copy into buffer
  0 debuglen debugstr + c!     \ terminate '\0'
  debugstr bootmsg-error
;

\ Usage: 42 error" error-txt"
: error" ( id level [text<">] -- )
  postpone s" state @
  IF
    ['] (error) compile,
  ELSE
    (error)
  THEN
; immediate

bootmsg-nvupdate
