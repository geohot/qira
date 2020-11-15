\ 7.4.7    Reset

defer reset-all    ( -- )

: no-reset-all
  s" reset-all is not available on this platform." type cr
  ;

' no-reset-all to reset-all 

\ OpenBOOT knows reset as well.
: reset reset-all ;
