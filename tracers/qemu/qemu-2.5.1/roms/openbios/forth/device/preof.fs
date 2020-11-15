\ tag: historical and pre open firmware fcode functions
\ 
\ this code implements IEEE 1275-1994 ch. H.2.2 and 5.3.1.1.1
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

\ H.2.2 Non-implemented FCodes
\ Pre-Open Firmware systems assigned the following FCode numbers,
\ but the functions were not supported. These FCode numbers stay 
\ reserved to avoid confusion.

: non-implemented 
  ." Non-implemented historical or pre-Open Firmware FCode occured." cr 
  end0
  ;

: adr-mask		non-implemented ;
: b(code)		non-implemented ;
: 4-byte-id		non-implemented ;
: convert		non-implemented ;
: frame-buffer-busy?	non-implemented ;
: poll-packet		non-implemented ;
: return-buffer		non-implemented ;
: set-token-table	non-implemented ;
: set-table		non-implemented ;
: xmit-packet		non-implemented ;

\ historical fcode words defined by 5.3.1.1.1

30000 constant fcode-version    \ this opcode is considered obsolete
30000 constant firmware-version \ this opcode is considered obsolete

\ historical - Returns the type of processor.
\ 0x5 indicates SPARC, other values are not used.
\ ?? this could be set by the kernel during bootstrap.
deadbeef constant processor-type ( -- processor-type )

: memmap		non-implemented ;
: >physical		non-implemented ;
: my-params 		non-implemented ;
: intr			non-implemented ;
: driver		non-implemented ;
: group-code		non-implemented ;
: probe 		non-implemented ;
: probe-virtual 	non-implemented ;
