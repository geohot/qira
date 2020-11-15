\ implements split-before, split-after and left-split 
\ as described in 4.3 (Path resolution)

\ delimeter returned in R-string
: split-before ( addr len delim -- addr-R len-R addr-L len-L ) 
  0 rot dup >r 0 ?do
    ( str char cnt R: len <sys> )
    2 pick over + c@ 2 pick = if leave then
    1+
  loop
  nip
  2dup + r> 2 pick -
  2swap
;

\ delimeter returned in L-string
: split-after ( addr len delim -- addr-R len-R addr-L len-L ) 
  over 1- rot dup >r 0 ?do
    ( str char cnt R: len <sys> )
    2 pick over + c@ 2 pick = if leave then
    1-
	loop
  nip
	dup 0 >= if 1+ else drop r@ then
	2dup + r> 2 pick -
  2swap
;

\ delimiter not returned
: left-split ( addr len delim -- addr-R len-R addr-L len-L )
  0 rot dup >r 0 ?do
    ( str char cnt R: len <sys> )
    2 pick i + c@ 2 pick = if leave then
    1+
  loop
  nip
  2dup + 1+ r> 2 pick -
  dup if 1- then
  2swap
;

\ delimiter not returned [THIS FUNCTION IS NOT NEEDED]
: right-split ( addr len delim -- addr-R len-R addr-L len-L )
	dup >r
	split-after
	dup if 2dup + 1-
		c@ r@ = if 1- then then
	r> drop
;
