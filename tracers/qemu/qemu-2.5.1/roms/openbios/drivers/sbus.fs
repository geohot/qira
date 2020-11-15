\ -------------------------------------------------------------------------
\ SBus encode/decode unit
\ -------------------------------------------------------------------------

: decode-unit-sbus ( str len -- id lun )
  ascii , left-split
  ( addr-R len-R addr-L len-L )
  parse-hex
  -rot parse-hex
  swap
;

: encode-unit-sbus ( id lun -- str len)
  swap
  pocket tohexstr
  " ," pocket tmpstrcat >r
  rot pocket tohexstr r> tmpstrcat drop
;

\ Convert sbus unit (from decode-unit) to physical address using
\ sbus node ranges property

: sbus-unit>addr ( phys.lo phys.hi -- phys.lo phys.hi -1 | 0 )
  " ranges" my-self ihandle>phandle
  get-package-property 0= if  ( phys.lo phys.hi prop prop-len )
    begin
      2over swap drop 0 swap  \ force phys.lo to zero for matching
      2swap  ( unit.phys.lo unit.phys.hi 0 phys.hi res prop prop-len )
      0 -rot  ( unit.phys.lo unit.phys.hi res prop prop-len )
      2 0 do
        decode-int -rot >r >r  ( unit.phys.lo unit.phys.hi res phys.x -- R: prop-len prop )
        rot  ( unit.phys.lo res phys.x phys.hi )
        = if
          1+
        then  ( unit.phys.lo res )
        r> r>  ( unit.phys.lo res prop prop-len )
      loop
      rot  ( prop prop-len res )
      2 = if  \ did we match the unit address? if so, return the physical address
        decode-phys 2swap 2drop 2swap  ( unit.phys.lo unit.phys.hi phys.lo phys.hi )
        drop 0 d+   \ force unit.phys.hi to zero and add address for final offset
        -1 exit
      else
        decode-phys 2drop decode-int drop   \ drop the size and carry on
      then
    dup 0= until
    2drop 2drop 0
  then
;

: map-in-sbus ( phys.lo phys.hi size )
  >r sbus-unit>addr if
    r@ " map-in" $call-parent
  then
  r> drop
;

: map-out-sbus ( virt size )
  " map-out" $call-parent
;

\ -------------------------------------------------------------------------
\ SBus probe
\ -------------------------------------------------------------------------

: probe-self-sbus ( arg-adr arg-len reg-adr reg-len fcode-adr fcode-len -- )

  0 to probe-fcode?

  ['] decode-unit-sbus catch if
    2drop 2drop 2drop 2drop
    exit
  then

  h# 10000 map-in-sbus

  dup cpeek if
    dup h# f1 = swap h# fd = or if
      new-device
      >r set-args r>
      dup 1 byte-load
      finish-device

      -1 to probe-fcode?
    else
      nip nip nip nip
      ." Invalid FCode start byte" cr
    then
  else
    nip nip nip nip
  then

  h# 10000 map-out-sbus
;
