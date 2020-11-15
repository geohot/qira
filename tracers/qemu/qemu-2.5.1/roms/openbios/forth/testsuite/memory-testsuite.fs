\ this is the memory management testsuite.
\ 
\ run it with   paflof < memory-testsuite.fs 2>/dev/null

s" memory.fs" included

\ dumps all free-list entries
\ useful for debugging.

: dump-freelist ( -- )
  ." Dumping freelist:" cr
  free-list @

  \ If the free list is empty we notify the user.
  dup 0= if ."   empty." drop cr exit then
  
  begin dup 0<> while
    dup ." entry 0x" .			\ print pointer to entry
    dup cell+ @ ." , next=0x" u.	\ pointer to next entry
    dup @ ." , size=0x" u. cr		\ len of current entry

    cell+ @
  repeat
  cr drop
  ;

\ simple testsuite. run testsuite-init to initialize
\ with some dummy memory in the dictionary.
\ run testsuite-test[1..3] for different tests.

: testsuite-init ( -- )
  here 40000 cell+ dup allot ( -- ptr len )
  init-mem

  ." start-mem = 0x" start-mem @ . cr
  ." end-mem   = 0x" end-mem @ . cr
  ." free-list = 0x" free-list @ . cr
  
  ." Memory management initialized." cr
  dump-freelist
  ;

: testsuite-test1 ( -- )
  ." Test No. 1: Allocating all available memory (256k)" cr

  40000 alloc-mem
  dup 0<> if 
    ." worked, ptr=0x" dup .
  else
    ." did not work."
  then
  cr

  dump-freelist
  ." Freeing memory." cr
  ." stack=" .s cr
  free-mem
  dump-freelist
  ;
  
: testsuite-test2 ( -- )
  ." Test No. 2: Allocating 5 blocks" cr
  4000 alloc-mem
  4000 alloc-mem
  4000 alloc-mem
  4000 alloc-mem
  4000 alloc-mem
  
  ." Allocated 5 blocks. Stack:" cr .s cr

  dump-freelist
  
  ." Freeing Block 2" cr
  3 pick free-mem dump-freelist

  ." Freeing Block 4" cr
  over free-mem dump-freelist

  ." Freeing Block 3" cr
  2 pick free-mem dump-freelist

  ." Cleaning up blocks 1 and 5" cr
  free-mem	\ Freeing block 5
  dump-freelist
  3drop		\ blocks 4, 3, 2
  free-mem
  
  dump-freelist
  ;

: testsuite-test3 ( -- )
  ." Test No. 3: freeing illegal address 0xdeadbeef." cr
  deadbeef free-mem
  dump-freelist
  ;
  
: testsuite ( -- )
  testsuite-init
  testsuite-test1
  testsuite-test2
  testsuite-test3
  ;

testsuite

bye
