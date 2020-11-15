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


\ Use the HPET to calculate various frequencies.

\ Make HPET run.
1 10 hpet!

\ Set PMC1 to count CPU cycles.
f00 mmcr0!

d# 1000000000000000 4 hpet@ / CONSTANT hpet-freq

: get-times  tbl@ pmc1@ f0 hpet@ ;

\ Calculate the CPU and TB frequencies.
: calibrate  get-times dup >r swap >r swap >r hpet-freq d# 100 / + >r
             BEGIN get-times dup r@ < WHILE 3drop REPEAT r> drop
             rot r> - ffffffff and \ TB
             rot r> - ffffffff and \ CPU
             rot r> - >r           \ HPET
             hpet-freq * r@ / swap
             hpet-freq * r> / ;

: round-to  tuck 2/ + over / * ;
calibrate TO tb-frequency d# 100000000 round-to TO cpu-frequency

\ Stop HPET.
0 10 hpet!
