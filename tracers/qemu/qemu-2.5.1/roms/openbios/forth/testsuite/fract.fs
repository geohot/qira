\ tag: forth fractal example
\ 
\ Copyright (C) 2002, 2003 Volker Poplawski <volker@poplawski.de>
\                          Stefan Reinauer

\ This example even fits in a signature ;-)

\ hex 4666 dup negate do i 4000 dup 2* negate do 2a 0 dup 2dup 1e 0 do
\ 2swap * d >>a 4 pick + -rot - j + dup dup * e >>a rot dup dup * e >>a 
\ rot swap 2dup + 10000 > if 3drop 2drop 20 0 dup 2dup leave then loop 
\ 2drop 2drop type 268 +loop cr drop 5de +loop


: fract
4666 dup negate
do
    i 4000 dup 2* negate
    do
        2a 0 dup 2dup 1e 0
	do
	    2swap * d >>a 4 pick +
	    -rot - j +
	    dup dup * e >>a rot
	    dup dup * e >>a rot
	    swap
	    2dup + 10000 > if
	        3drop 2drop 20 0 dup 2dup leave
	    then
	loop
	2drop 2drop
	emit
    268 +loop
    cr drop
5de +loop
;
