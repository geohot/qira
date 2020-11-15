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


\ Client interface.

0 VALUE debug-client-interface?

\ First, the machinery.

VOCABULARY client-voc \ We store all client-interface callable words here.

6789  CONSTANT  sc-exit
4711  CONSTANT  sc-yield

VARIABLE  client-callback \ Address of client's callback function

: client-data  ciregs >r3 @ ;
: nargs  client-data la1+ l@ ;
: nrets  client-data la1+ la1+ l@ ;
: client-data-to-stack
  client-data 3 la+ nargs 0 ?DO dup l@ swap la1+ LOOP drop ;
: stack-to-client-data
  client-data nargs nrets + 2 + la+ nrets 0 ?DO tuck l! /l - LOOP drop ;

: call-client ( args len client-entry -- )
  \ (args, len) describe the argument string, client-entry is the address of
  \ the client's .entry symbol, i.e. where we eventually branch to.
  \ ciregs is a variable that describes the register set of the host processor,
  \ see slof/fs/exception.fs for details
  \ client-entry-point maps to client_entry_point in slof/entry.S which is
  \ the SLOF entry point when calling a SLOF client interface word from the
  \ client.
  \ We pass the arguments for the client in R6 and R7, the client interface
  \ entry point address is passed in R5.
  >r  ciregs >r7 !  ciregs >r6 !  client-entry-point @ ciregs >r5 !
  \ Initialise client-stack-pointer
  cistack ciregs >r1 !
  \ jump-client maps to call_client in slof/entry.S
  \ When jump-client returns, R3 holds the address of a NUL-terminated string
  \ that holds the client interface word the client wants to call, R4 holds
  \ the return address.
  r> jump-client drop
  BEGIN
    client-data-to-stack
    \ Now create a Forth-style string, look it up in the client dictionary and
    \ execute it, guarded by CATCH. Result of xt == 0 is stored on the return
    \ stack
    client-data l@ zcount
    \ XXX: Should only look in client-voc...
    ALSO client-voc $find PREVIOUS
    dup 0= >r IF 
      CATCH
      \ If a client interface word needs some special treatment, like exit and
      \ yield, then the implementation needs to use THROW to indicate its needs
      ?dup IF
        dup CASE
          sc-exit OF drop r> drop EXIT ENDOF
          sc-yield OF drop r> drop EXIT ENDOF
        ENDCASE
        \ Some special call was made but we don't know that to do with it...
        THROW
      THEN
      stack-to-client-data
    ELSE
      cr type ."  NOT FOUND"
    THEN
    \ Return to the client
    r> ciregs >r3 !  ciregs >r4 @ jump-client 
  UNTIL ;

: flip-stack ( a1 ... an n -- an ... a1 )  ?dup IF 1 ?DO i roll LOOP THEN ;

: (callback) ( "service-name<>" "arguments<cr>" -- )
  client-callback @  \ client-callback points to the function prolog
  dup 8 + @ ciregs >r2 !  \ Set up the TOC pointer (???)
  @ call-client ;  \ Resolve the function's address from the prolog
' (callback) to callback

: (continue-client)
  s" "  \ make call-client happy, client won't use the string anyways.
  ciregs >r4 @ call-client ;
' (continue-client) to continue-client

\ Utility.
: string-to-buffer ( str len buf len -- len' )
  2dup erase rot min dup >r move r> ;

\ Now come the actual client interface words.

ALSO client-voc DEFINITIONS

: exit  sc-exit THROW ;

: yield  sc-yield THROW ;

: test ( zstr -- missing? )
   \ XXX: Should only look in client-voc...
   zcount
   debug-client-interface? IF
      ." ci: test " 2dup type cr
   THEN
   ALSO client-voc $find PREVIOUS IF
      drop FALSE
   ELSE
      2drop TRUE
   THEN 
;

: finddevice ( zstr -- phandle )
   zcount
   debug-client-interface? IF
      ." ci: finddevice " 2dup type cr
   THEN
   2dup " /memory" str= IF
     \ Workaround: grub passes /memory instead of /memory@0
     2drop
     " /memory@0"
   THEN
   find-node dup 0= IF drop -1 THEN
;

: getprop ( phandle zstr buf len -- len' )
   >r >r zcount rot                     ( str-adr str-len phandle   R: len buf )
   debug-client-interface? IF
      ." ci: getprop " 3dup . ." '" type ." '"
   THEN
   get-property
   debug-client-interface? IF
      dup IF ."  ** not found **" THEN
      cr
   THEN
   0= IF
      r> swap dup r> min swap >r move r>
   ELSE
      r> r> 2drop -1
   THEN
;

: getproplen ( phandle zstr -- len )
  zcount rot get-property 0= IF nip ELSE -1 THEN ;

: setprop ( phandle zstr buf len -- size|-1 )
   dup >r            \ save len
   encode-bytes      ( phandle zstr prop-addr prop-len )
   2swap zcount rot  ( prop-addr prop-len name-addr name-len phandle )
   current-node @ >r \ save current node
   set-node          \ change to specified node
   property          \ set property
   r> set-node       \ restore original node
   r>                \ always return size, because we can not fail.
;

\ VERY HACKISH
: canon ( zstr buf len -- len' )
   2dup erase
   >r >r zcount
   >r dup c@ [char] / = IF
      r> r> swap r> over >r min move r>
   ELSE
      r> find-alias ?dup 0= IF
         r> r> 2drop -1
      ELSE
         dup -rot r> swap r> min move
      THEN
   THEN
;

: nextprop ( phandle zstr buf -- flag ) \ -1 invalid, 0 end, 1 ok
  >r zcount rot next-property IF r> zplace 1 ELSE r> drop 0 THEN ; 

: open ( zstr -- ihandle )
   zcount
   debug-client-interface? IF
      ." ci: open " 2dup type cr
   THEN
   open-dev
;

: close ( ihandle -- )
    debug-client-interface? IF
	." ci: close " dup . cr
    THEN
    s" stdin" get-chosen IF
	decode-int nip nip over = IF
	    \ End of life of SLOF now, call platform quiesce as quiesce
	    \ is an undocumented extension and not everybody supports it
	    close-dev
	    quiesce
	ELSE
	    close-dev
	THEN
    ELSE
	close-dev
    THEN
;

\ Now implemented: should return -1 if no such method exists in that node
: write ( ihandle str len -- len' )      rot s" write" rot
	['] $call-method CATCH IF 2drop 3drop -1 THEN ;
: read  ( ihandle str len -- len' )      rot s" read"  rot
	['] $call-method CATCH IF 2drop 3drop -1 THEN ;
: seek  ( ihandle hi lo -- status  ) swap rot s" seek" rot
	['] $call-method CATCH IF 2drop 3drop -1 THEN ;

\ A real claim implementation: 3.2% memory fat :-)
: claim  ( addr len align -- base )
   debug-client-interface? IF
      ." ci: claim " .s cr
   THEN
   dup  IF  rot drop
      ['] claim CATCH  IF  2drop -1  THEN
   ELSE
      ['] claim CATCH  IF  3drop -1  THEN
   THEN
;

: release ( addr len -- )
   debug-client-interface? IF
      ." ci: release " .s cr
   THEN
   release
;

: instance-to-package ( ihandle -- phandle )
  ihandle>phandle ;

: package-to-path ( phandle buf len -- len' )
  2>r node>path 2r> string-to-buffer ;
: instance-to-path ( ihandle buf len -- len' )
  2>r instance>path 2r> string-to-buffer ;
: instance-to-interposed-path ( ihandle buf len -- len' )
  2>r instance>qpath 2r> string-to-buffer ;

: call-method ( str ihandle arg ... arg -- result return ... return )
  nargs flip-stack zcount
  debug-client-interface? IF
     ." ci: call-method " 2dup type cr
  THEN
  rot ['] $call-method CATCH
  nrets 0= IF drop ELSE \ if called with 0 return args do not return the catch result
     dup IF nrets 1 ?DO -444 LOOP THEN
     nrets flip-stack 
  THEN
;

\ From the PAPR.
: test-method ( phandle str -- missing? )
   zcount
   debug-client-interface? IF
      ." ci: test-method " 2dup type cr
   THEN
   rot find-method dup IF nip THEN 0=
;

: milliseconds  milliseconds ;

: start-cpu ( phandle addr r3 -- )
  >r >r 
  s" reg" rot get-property 0= IF drop l@ 
    ELSE true ABORT" start-cpu called with invalid phandle" THEN 
  r> r> of-start-cpu drop
;

\ Quiesce firmware and assert that all hardware is in a sane state
\ (e.g. assert that no background DMA is running anymore)
: quiesce  ( -- )
   debug-client-interface? IF
      ." ci: quiesce" cr
   THEN
   \ The main quiesce call is defined in quiesce.fs
   quiesce
;

\
\ Standard for Boot, defined in 6.3.2.5:
\
: boot  ( zstr -- )
   zcount
   debug-client-interface? IF
      ." ci: boot " 2dup type cr
   THEN
   " boot " 2swap $cat " boot-command" $setenv (nvupdate)
   reset-all
;

\
\ User Interface, defined in 6.3.2.6
\
: interpret ( ... zstr -- result ... )
   zcount
   debug-client-interface? IF
      ." ci: interpret " 2dup type cr
   THEN
   ['] evaluate CATCH
;

\ Allow the client to register a callback
: set-callback ( newfunc -- oldfunc )
  client-callback @ swap client-callback ! ;

PREVIOUS DEFINITIONS
