[IFDEF] CONFIG_DRIVER_PCI

: pci-addr-encode ( addr.lo addr.mi addr.hi )
  rot >r swap >r 
  encode-int 
  r> encode-int encode+ 
  r> encode-int encode+
  ;
 
: pci-len-encode ( len.lo len.hi )
  encode-int 
  rot encode-int encode+ 
  ;

\ Get region offset for BAR reg
: pci-bar-offset@ ( bar-reg -- off.lo off.hi -1 | 0 )
  " reg" active-package get-package-property 0= if
    begin
      decode-phys    \ ( reg prop prop-len phys.lo phys.mid phys.hi )
      ff and 5 pick = if
        >r >r 3drop r> r>
        -1 exit
      else
        2drop
      then
      \ Drop the size as we don't need it
      decode-int drop decode-int drop
      dup 0=
    until
    3drop
    0 exit
  else
    0
  then
  ;

\ Get region size for BAR reg
: pci-bar-size@ ( bar-reg -- size )
  " reg" active-package get-package-property 0= if
    begin
      decode-phys    \ ( reg prop prop-len phys.lo phys.mid phys.hi )
      ff and 5 pick = if
        2drop decode-int drop
        decode-int
        >r 3drop r>
        exit
      else
        2drop decode-int drop
        decode-int drop
      then
      dup 0=
    until
    3drop
    0    \ default size of 0 if BAR not found
  then
  ;

\ Get base address for configured BAR reg
: pci-bar-base@ ( bar-reg -- addr.lo addr.hi -1 | 0 )
  " assigned-addresses" active-package get-package-property 0= if
    begin
      decode-phys    \ ( reg prop prop-len phys.lo phys.mid phys.hi )
      ff and 5 pick = if
        >r >r 3drop r> r>
        -1 exit
      else
        2drop
      then
      \ Drop the size as we don't need it
      decode-int drop decode-int drop
      dup 0=
    until
    3drop
    0 exit
  else
    0
  then
  ;

\ Get PCI bus address and size for configured BAR reg
: pci-bar>pci-region  ( bar-reg -- addr.lo addr.hi size )
  dup
  >r pci-bar-offset@ if
    swap r@ pci-bar-base@ if
      swap d+
    then
    swap r@ pci-bar-size@
  then
  r> drop
  ;

[THEN]
