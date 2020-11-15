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

\ I/O accesses.

\ Legacy I/O accesses.
: >io  f4000000 + ;

: io-c!  >io rb! ;
: io-c@  >io rb@ ;

: io-w!  >io rw! ;
: io-w@  >io rw@ ;

\ Accessing the SIO config registers.
: siocfg!  2e io-c! 2f io-c! ;
: siocfg@  2e io-c! 2f io-c@ ;
