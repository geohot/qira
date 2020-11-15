\ 
\ ioapic and local apic tester
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

hex

fee00000 constant lapic_base
fec00000 constant ioapic_base

: read_lapic ( regoffset -- value )
  lapic_base + l@
  ;

: write_lapic ( value regoffset -- )
  lapic_base + l!
  ;

: read_ioapic ( regoffset -- low_value high_value )
  2* 10 + dup 
  ioapic_base l! ioapic_base 4 cells + l@
  swap 1+ 
  ioapic_base l! ioapic_base 4 cells + l@
  ;

: write_ioapic ( low high regoffset -- )
  2* 10 + dup 					( low high offs offs ) 
  ioapic_base l! rot ioapic_base 4 cells + l!	( high offs )
  1+
  ioapic_base l! ioapic_base 4 cells + l!	( high offs )
  ;

: test-lapic 
  s" Dumping local apic:" type cr
  3f0 0 do
    i dup ( lapic_base + ) s" 0x" type . s" = 0x" type read_lapic space . 
    i 30 and 0= if cr then
  10 +loop
  cr
  ;

: test-ioapic
  s" Dumping io apic:" type cr
  17 0 do 
    i dup s" irq=" type . read_ioapic s" = 0x" type . s" ." type . 
    i 1 and 0<> if 
      cr
    then
  loop
  cr
  ;

: dump-apics
  test-lapic
  test-ioapic
  ;

\ tag: apic test utility
