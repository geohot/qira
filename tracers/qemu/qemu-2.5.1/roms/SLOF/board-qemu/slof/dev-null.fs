\ Introduce a dummy console that will eat away all chars and make all
\ the components dependent on stdout happy.

new-device
" devnull-console" device-name

: open true ;
: close ;

: write ( adr len -- actual )
  nip
;

: read  ( adr len -- actual )
  nip
;

: setup-alias
    " devnull-console" find-alias 0= IF
        " devnull-console" get-node node>path set-alias
    ELSE
        drop
    THEN
;

: dummy-term-emit drop ;
: dummy-term-key  0 ;
: dummy-term-key? FALSE ;

' dummy-term-emit to emit
' dummy-term-key  to key
' dummy-term-key? to key?

setup-alias
finish-device
