\ *****************************************************************************
\ * Copyright (c) 2004, 2012 IBM Corporation
\ * All rights reserved.
\ * This program and the accompanying materials
\ * are made available under the terms of the BSD License
\ * which accompanies this distribution, and is available at
\ * http://www.opensource.org/licenses/bsd-license.php
\ *
\ * Contributors:
\ *     IBM Corporation - initial implementation
\ ****************************************************************************/


\ configuration variables

wordlist CONSTANT envvars

\ list the names in  envvars
: listenv  ( -- )
   get-current envvars set-current  words  set-current
;

\ create a definition in  envvars
: create-env ( "name" -- )
   get-current  envvars set-current  CREATE  set-current
;

\ lay out the data for the separate envvar types
: env-int     ( n -- )  1 c, align , DOES> char+ aligned @ ;
: env-bytes   ( a len -- )
   2 c, align dup , here swap dup allot move
   DOES> char+ aligned dup @ >r cell+ r>
;
: env-string  ( str len -- )  3 c, align dup , here over allot swap move DOES> char+ aligned dup @ >r cell+ r> ;
: env-flag    ( f -- )  4 c, c, DOES> char+ c@ 0<> ;
: env-secmode ( sm -- )  5 c, c, DOES> char+ c@ ;

\ create default envvars
: default-int     ( n "name" -- )      create-env env-int ;
: default-bytes   ( a len "name" -- )  create-env env-bytes ;
: default-string  ( a len "name" -- )  create-env env-string ;
: default-flag    ( f "name" -- )      create-env env-flag ;
: default-secmode ( sm "name" -- )     create-env env-secmode ;

: set-option ( option-name len option len -- )
   2swap encode-string
   2swap s" /options" find-node dup IF set-property ELSE drop 2drop 2drop THEN
;

\ find an envvar's current and default value, and its type
: findenv ( name len -- adr def-adr type | 0 )
   2dup envvars voc-find dup 0<> IF ( ABORT" not a configuration variable" )
      link> >body char+ >r (find-order) link> >body dup char+ swap c@ r> swap
   ELSE
      nip nip
   THEN
;


: test-flag ( param len -- true | false )
   2dup s" true" string=ci -rot s" false" string=ci or
;

: test-secmode ( param len -- true | false )
   2dup s" none" string=ci -rot 2dup s" command" string=ci -rot s" full"
   string=ci or or
;

: test-int ( param len -- true | false )
  $dh-number IF false ELSE drop true THEN
;

: findtype ( param len name len -- param len name len type )
   2dup findenv                         \ try to find type of envvar
   dup IF                               \ found a type?
      nip nip
      EXIT
   THEN

   \ No type found yet, try to auto-detect:
   drop 2swap
   2dup test-flag IF
      4 -rot                         \ boolean type
   ELSE
      2dup test-secmode IF
         5 -rot                      \ secmode type
      ELSE
         2dup test-int IF
            1 -rot                   \ integer type
         ELSE
            2dup test-string
            IF 3 ELSE 2 THEN         \ 3 = string, 2 = default to bytes
            -rot
         THEN
      THEN
   THEN
   rot
   >r 2swap r>
;

\ set an envvar
: $setenv ( param len name len -- )
   4dup set-option
   findtype
   -rot $CREATE
   CASE
      1 OF $dh-number IF 0 THEN env-int ENDOF \ XXX: wants decimal and 0x...
      2 OF env-bytes ENDOF
      3 OF env-string ENDOF
      4 OF evaluate env-flag ENDOF
      5 OF evaluate env-secmode ENDOF \ XXX: recognize none, command, full
   ENDCASE
;

\ print an envvar
: (printenv) ( adr type -- )
   CASE
   1 OF aligned @ . ENDOF
   2 OF aligned dup cell+ swap @ swap . . ENDOF
   3 OF aligned dup @ >r cell+ r> type ENDOF
   4 OF c@ IF ." true" ELSE ." false" THEN ENDOF
   5 OF c@ . ENDOF \ XXX: print symbolically
   ENDCASE
;

: .printenv-header ( -- )
   cr
   s" ---environment variable--------current value-------------default value------"
   type cr
;

DEFER old-emit
0 VALUE emit-counter

: emit-and-count emit-counter 1 + to emit-counter old-emit ;

: .enable-emit-counter
   0 to emit-counter
   ['] emit behavior to old-emit
   ['] emit-and-count to emit
;

: .disable-emit-counter
   ['] old-emit behavior to emit
;

: .spaces ( number-of-spaces -- )
   dup 0 > IF
      spaces
   ELSE
      drop space
   THEN
;

: .print-one-env ( name len -- )
   3 .spaces
   2dup dup -rot type 1c swap - .spaces
   findenv rot over
   .enable-emit-counter
   (printenv) .disable-emit-counter
   1a emit-counter - .spaces
   (printenv)
;

: .print-all-env
   .printenv-header
   envvars cell+
   BEGIN
      @ dup
   WHILE
      dup link> >name
      name>string .print-one-env cr
   REPEAT
   drop
;

: printenv
   parse-word dup 0= IF
      2drop .print-all-env
   ELSE
      findenv dup 0= ABORT" not a configuration variable"
      rot over cr ." Current: " (printenv)
      cr ." Default: " (printenv)
   THEN
;

\ set envvar(s) to default value
: (set-default)  ( def-xt -- )
   dup >name name>string $CREATE dup >body c@ >r execute r> CASE
   1 OF env-int ENDOF
   2 OF env-bytes ENDOF
   3 OF env-string ENDOF
   4 OF env-flag ENDOF
   5 OF env-secmode ENDOF ENDCASE
;

\ Environment variables might be board specific

#include <envvar_defaults.fs>

VARIABLE nvoff \ offset in envvar partition

: (nvupdate-one) ( adr type -- "value" )
   CASE
   1 OF aligned @ (.d) ENDOF
   2 OF drop 0 0 ENDOF
   3 OF aligned dup @ >r cell+ r> ENDOF
   4 OF c@ IF s" true" ELSE s" false" THEN ENDOF
   5 OF c@ (.) ENDOF \ XXX: print symbolically
   ENDCASE
;

: nvupdate-one   ( def-xt -- )
   >r nvram-partition-type-common get-nvram-partition       ( part.addr part.len FALSE|TRUE R: def-xt )
   ABORT" No valid NVRAM." r>      ( part.addr part.len def-xt )
   >name name>string               ( part.addr part.len var.a var.l )
   2dup findenv nip (nvupdate-one)
   ( part.addr part.len var.addr var.len val.addr val.len )
   internal-add-env
   drop
;

: (nvupdate) ( -- )
   nvram-partition-type-common get-nvram-partition ABORT" No valid NVRAM."
   erase-nvram-partition drop
   envvars cell+
   BEGIN @ dup WHILE dup link> nvupdate-one REPEAT
   drop
;

: nvupdate ( -- )
   ." nvupdate is obsolete." cr
;

: set-default
   parse-word envvars voc-find
   dup 0= ABORT" not a configuration variable" link> (set-default)
;

: (set-defaults)
   envvars cell+
   BEGIN @ dup WHILE dup link> (set-default) REPEAT
   drop
;

\ Preset nvram variables in RAM, but do not overwrite them in NVRAM
(set-defaults)

: set-defaults
   (set-defaults) (nvupdate)
;

: setenv  parse-word ( skipws ) 0d parse -leading 2swap $setenv (nvupdate) ;

: get-nv  ( -- )
   nvram-partition-type-common get-nvram-partition ( addr offset not-found | not-found ) \ find partition header
   IF
      ." No NVRAM common partition, re-initializing..." cr
      internal-reset-nvram
      (nvupdate)
      nvram-partition-type-common get-nvram-partition IF ." NVRAM seems to be broken." cr EXIT THEN
   THEN
   \ partition header found: read data from nvram
   drop ( addr )           \ throw away offset
   BEGIN
      dup rzcount  dup     \ make string from offset and make condition
   WHILE                   ( offset offset length )
      2dup [char] = split  \ Split string at equal sign (=)
                           ( offset offset length name len param len )
      2swap                ( offset offset length param len name len )
      $setenv              \ Set envvar
      nip                  \ throw away old string begin
      + 1+                 \ calc new offset
   REPEAT
   2drop drop              \ cleanup
;

get-nv

: check-for-nvramrc  ( -- )
   use-nvramrc?  IF
      s" Executing following code from nvramrc: "
      s" nvramrc" evaluate $cat
      nvramlog-write-string-cr
      s" (!) Executing code specified in nvramrc" type
      cr s"  SLOF Setup = " type
      \ to remove the string from the console if the nvramrc is broken
      \ we need to know how many chars are printed
      .enable-emit-counter
      s" nvramrc" evaluate ['] evaluate  CATCH  IF
         \ dropping the rest of the nvram string
         2drop
         \ delete the chars we do not want to see
         emit-counter 0  DO  8 emit  LOOP
         s" (!) Code in nvramrc triggered exception. "
         2dup nvramlog-write-string
         type cr 12 spaces s" Aborting nvramrc execution" 2dup
         nvramlog-write-string-cr type cr
         s"  SLOF Setup = " type
      THEN
      .disable-emit-counter
   THEN
;


: (nv-findalias) ( alias-ptr alias-len -- pos )
   \ create a temporary empty string
   here 0
   \ append "devalias " to the temporary string
   s" devalias " string-cat
   \ append "<name-str>" to the temporary string
   3 pick 3 pick string-cat
   \ append a SPACE character to the temporary string
   s"  " string-cat
   \ get nvramrc
   s" nvramrc" evaluate
   \ get position of the temporary string inside of nvramrc
   2swap find-substr
   nip nip
;

: (nv-build-real-entry) ( name-ptr name-len dev-ptr dev-len -- str-ptr str-len )
   \ create a temporary empty string
   2swap here 0
   \ append "devalias " to the temporary string
   s" devalias " string-cat
   \ append "<name-ptr>" to the temporary string
   2swap string-cat
   \ append a SPACE character to the temporary string
   s"  " string-cat
   \ append "<dev-ptr> to the temporary string
   2swap string-cat
   \ append a CR character to the temporary string
   0d char-cat
   \ append a LF character to the temporary string
   0a char-cat
;

: (nv-build-null-entry) ( name-ptr name-len dev-ptr dev-len -- str-ptr str-len )
   4drop here 0
;

: (nv-build-nvramrc) ( name-str name-len dev-str dev-len xt-build-entry -- )
   \ *** PART 1: check if there is still an alias definition available ***
   ( alias-ptr alias-len path-ptr path-ptr call-build-entry alias-pos )
   4 pick 4 pick (nv-findalias)
   \ if our alias definition is a new one
   dup s" nvramrc" evaluate nip >= IF
      \ call-build-entry
      drop execute
      \ append content of "nvramrc" to the temporary string
      s" nvramrc" evaluate string-cat
      \ Allocate the temporary string
      dup allot
      \ write the string into nvramrc
      s" nvramrc" $setenv
   ELSE  \ if our alias is still defined in nvramrc
      \ *** PART 2: calculate the memory size for the new content of nvramrc ***
      \ add number of bytes needed for nvramrc-prefix to number of bytes needed
      \ for the new entry
      5 pick 5 pick 5 pick 5 pick 5 pick execute nip over +
      ( alias-ptr alias-len path-ptr path-ptr build-entry-xt alias-pos tmp-len )
      \ add number of bytes needed for nvramrc-postfix
      s" nvramrc" evaluate 3 pick string-at
      2dup find-nextline string-at nip +
      \ *** PART 3: build the new content ***
      \ allocate enough memory for new content
      alloc-mem 0
      ( alias-ptr alias-len path-ptr path-ptr build-entry-xt alias-pos mem len )
      \ add nvramrc-prefix
      s" nvramrc" evaluate drop 3 pick string-cat
      \ add new entry
      rot >r >r >r execute r> r> 2swap string-cat
      ( mem, len ) ( R: alias-pos )
      \ add nvramrc-postfix
      s" nvramrc" evaluate r> string-at
      2dup find-nextline string-at string-cat
      ( mem len )
      \ write the temporary string into nvramrc and clean up memory
      2dup s" nvramrc" $setenv free-mem
   THEN
;

: $nvalias ( name-str name-len dev-str dev-len -- )
   4dup ['] (nv-build-real-entry) (nv-build-nvramrc)
   set-alias
   s" true" s" use-nvramrc?" $setenv
   (nvupdate)
;

: nvalias ( "alias-name< >device-specifier<eol>" -- )
   parse-word parse-word dup 0<> IF
      $nvalias
   ELSE
      2drop 2drop
      cr
      "    Usage: nvalias (""alias-name< >device-specifier<eol>"" -- )" type
      cr
   THEN    
;

: $nvunalias ( name-str name-len -- )
   s" " ['] (nv-build-null-entry) (nv-build-nvramrc)
   (nvupdate)
;

: nvunalias ( "alias-name< >" -- )
   parse-word $nvunalias
;

: diagnostic-mode? ( -- diag-switch? ) diag-switch? ;

