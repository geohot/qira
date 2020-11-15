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

deadbeef here l!
here c@ de = CONSTANT ?bigendian
here c@ ef = CONSTANT ?littleendian


?bigendian [IF]

: x!-le >r xbflip r> x! ;
: x@-le x@ xbflip ;

: l!-le  >r lbflip r> l! ;
: l@-le  l@ lbflip ;

: w!-le  >r wbflip r> w! ;
: w@-le  w@ wbflip ;

: rx!-le  >r xbflip r> rx! ;
: rx@-le  rx@ xbflip ;

: rl!-le  >r lbflip r> rl! ;
: rl@-le  rl@ lbflip ;

: rw!-le  >r wbflip r> rw! ;
: rw@-le  rw@ wbflip ;

: l!-be  l! ;
: l@-be  l@ ;

: w!-be  w! ;
: w@-be  w@ ;

: rl!-be  rl! ;
: rl@-be  rl@ ;

: rw!-be  rw! ;
: rw@-be  rw@ ;


[ELSE]

: x!-le x! ;
: x@-le x@ ;

: l!-le  l! ;
: l@-le  l@ ;

: w!-le  w! ;
: w@-le  w@ ;

: rx!-le  rx! ;
: rx@-le  rx@ ;

: rl!-le  rl! ;
: rl@-le  rl@ ;

: rw!-le  rw! ;
: rw@-le  rw@ ;

: l!-be  >r lbflip r> l! ;
: l@-be  l@ lbflip ;

: w!-be  >r wbflip r> w! ;
: w@-be  w@ wbflip ;

: rl!-be  >r lbflip r> rl! ;
: rl@-be  rl@ lbflip ;

: rw!-be  >r wbflip r> rw! ;
: rw@-be  rw@ wbflip ;

[THEN]
