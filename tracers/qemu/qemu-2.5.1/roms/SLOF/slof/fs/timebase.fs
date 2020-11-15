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
\ Define all timebase related words

: tb@  ( -- tb )
   BEGIN tbu@ tbl@ tbu@ rot over <> WHILE 2drop REPEAT
   20 lshift swap ffffffff and or
;

: milliseconds ( -- ms ) tb@ d# 1000 * tb-frequency / ;
: microseconds ( -- us ) tb@ d# 1000000 * tb-frequency / ;

: ms ( ms-to-wait -- ) milliseconds + BEGIN milliseconds over >= UNTIL drop ;
: get-msecs ( -- n ) milliseconds ;
: us  ( us-to-wait -- )  microseconds +  BEGIN microseconds over >= UNTIL  drop ;
