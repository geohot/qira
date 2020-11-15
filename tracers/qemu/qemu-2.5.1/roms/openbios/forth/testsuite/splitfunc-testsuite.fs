\ this is the splitfunc testsuite.
\ 
\ run it with   paflof < splitfunc-testsuite.fs 2>/dev/null

\ implements split-before, split-after and left-split 
\ as described in 4.3 (Path resolution)

s" splitfunc.fs" included
 
: test-split
 s" var/log/messages" 2dup

 cr ." split-before test:" cr
 2dup ." String: " type cr
 2f split-before
 2swap 
 ." initial: " type cr ." remainder:" type cr
 cr
 ." split-after test:" cr
 2f split-after cr
 2swap 
 ." initial: " type cr ." remainder:" type cr

 ." foobar test" cr

 s" foobar" 2dup

 2f split-after cr
 2swap 
 ." initial: " type cr ." remainder:" type cr

 2f split-after cr
 2swap 
 ." initial: " type cr ." remainder:" type cr
 ;


  
