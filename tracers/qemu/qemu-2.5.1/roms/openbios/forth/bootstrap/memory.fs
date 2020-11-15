\ tag: forth memory allocation
\ 
\ Copyright (C) 2002-2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

\ 7.3.3.2 memory allocation

\ these need to be initialized by the forth kernel by now.
variable start-mem 0 start-mem !	\ start of memory
variable end-mem   0 end-mem   !	\ end of memory
variable free-list 0 free-list !	\ free list head

\ initialize necessary variables and write a valid 
\ free-list entry containing all of the memory.
\   start-mem: pointer to start of memory.
\   end-mem:   pointer to end of memory.
\   free-list: head of linked free list

: init-mem ( start-addr size )
  over dup
  start-mem !		\ write start-mem 
  free-list !		\ write first freelist entry
  2dup /n - swap !	\ write 'len'  entry
  over cell+ 0 swap !	\ write 'next' entry
  + end-mem  !		\ write end-mem 
  ;
 
\ --------------------------------------------------------------------

\ return pointer to smallest free block that contains 
\ at least nb bytes and the block previous the the 
\ actual block. On failure the pointer to the smallest
\ free block is 0.

: smallest-free-block ( nb -- prev ptr | 0 0 )
  0 free-list @
  fffffff 0 0 >r >r >r
  begin
    dup
  while
    ( nb prev pp R: best_nb best_pp )
    dup @ 3 pick r@ within if
      ( nb prev pp )
      r> r> r> 3drop            \ drop old smallest
      2dup >r >r dup @ >r       \ new smallest
    then
    nip dup                     \ prev = pp
    cell + @                    \ pp = pp->next
  repeat
  3drop r> drop r> r>
;


\ --------------------------------------------------------------------

\ allocate size bytes of memory
\ return pointer to memory (or throws an exception on failure).

: alloc-mem ( size -- addr )

  \ make it legal (and fast) to allocate 0 bytes
  dup 0= if exit then

  aligned			\ keep memory aligned.
  dup smallest-free-block	\ look up smallest free block.
  
  dup 0= if 
    \ 2drop
    -15 throw \ out of memory
  then
  
  ( al-size prev addr )
  
  \ If the smallest fitting block found is bigger than
  \ the size of the requested block plus 2*cellsize we
  \ can split the block in 2 parts. otherwise return a
  \ slightly bigger block than requested.

  dup @ ( d->len ) 3 pick cell+ cell+ > if
  
    \ splitting the block in 2 pieces.
    \ new block = old block + len field + size of requested mem
    dup 3 pick cell+ +	(  al-size prev addr nd )

    \ new block len = old block len - req. mem size - 1 cell
    over @		( al-size prev addr nd addr->len )
    4 pick		( ... al-size )
    cell+ -		( al-size prev addr nd nd nd->len )
    over !		( al-size prev addr nd )

    over cell+ @	( al-size prev addr nd addr->next )
    			\ write addr->next to nd->next
    over cell+ !	( al-size prev addr nd )
    over 4 pick swap !
  else
    \ don't split the block, it's too small.
    dup cell+ @
  then

  ( al-size prev addr nd )

  \ If the free block we got is the first one rewrite free-list
  \ pointer instead of the previous entry's next field.
  rot dup 0= if drop free-list else cell+ then
  ( al-size addr nd prev->next|fl )
  !
  nip cell+	\ remove al-size and skip len field of returned pointer

  ;


\ --------------------------------------------------------------------
  
\ free block given by addr. The length of the
\ given block is stored at addr - cellsize.
\ 
\ merge with blocks to the left and right 
\ immediately, if they are free.

: free-mem ( addr len -- )

  \ we define that it is legal to free 0-byte areas
  0= if drop exit then
  ( addr )
	
  \ check if the address to free is somewhere within
  \ our available memory. This fails badly on discontigmem
  \ architectures. If we need more RAM than fits on one 
  \ contiguous memory area we are too bloated anyways. ;)
  
  dup start-mem @ end-mem @ within 0= if
 \   ." free-mem: no such memory: 0x" u. cr
    exit
  then

  /n -				\ get real block address
  0 free-list @			( addr prev l )
  
  begin				\ now scan the free list
    dup 0<> if			\ only check len, if block ptr != 0
      dup dup @ cell+ + 3 pick < 
    else
      false
    then
  while 
    nip dup			\ prev=l
    cell+ @			\ l=l->next
  repeat

  ( addr prev l )

  dup 0<> if				\ do we have free memory to merge with?
  
    dup dup @ cell+ + 3 pick  = if	\ hole hit. adding bytes.
      \ freeaddr = end of current block -> merge
      ( addr prev l )
      rot @ cell+		( prev l f->len+cellsize )
      over @ +			\ add l->len
      over !			( prev l )
      swap over cell+ @		\ f = l; l = l->next;

      \ The free list is sorted by addresses. When merging at the
      \ start of our block we might also want to merge at the end
      \ of it. Therefore we fall through to the next border check
      \ instead of returning.
      true				\ fallthrough value
    else
      false				\ no fallthrough
    then
    >r					\ store fallthrough on ret stack
    
    ( addr prev l )

    dup 3 pick dup @ cell+ + = if	\ hole hit. real merging.
      \ current block starts where block to free ends.
      \ end of free block addr = current block -> merge and exit
      					( addr prev l )
      2 pick dup @			( f f->len ) 
      2 pick @ cell+ +			( f newlen )
      swap !				( addr prev l )
      3dup drop
      0= if
	free-list
      else
	2 pick cell+ 
      then				( value prev->next|free-list )
      !					( addr prev l )
      cell+ @ rot			( prev l->next addr )
      cell+ ! drop
      r> drop exit			\ clean up return stack
    then

    r> if 3drop exit then		\ fallthrough? -> exit
  then
  
  \ loose block - hang it before current.

  ( addr prev l )

  \ hang block to free in front of the current entry.
  dup 3 pick cell+ !			\ f->next = l;
  free-list @ = if			\ is block to free new list head?
    over free-list !
  then
  
  ( addr prev )
  dup 0<> if				\ if (prev) prev->next=f
    cell+ !
  else 
    2drop				\ no fixup needed. clean up.
  then
    
  ;
