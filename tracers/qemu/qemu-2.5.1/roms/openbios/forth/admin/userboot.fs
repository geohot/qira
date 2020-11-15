\ 7.4.3.5 User commands for booting

: boot		( "{param-text}<cr>" -- )
  linefeed parse

  \ Copy NVRAM parameters from boot-file to bootargs in case any parameters have
  \ been specified for the platform-specific boot code
  s" boot-file" $find drop execute
  encode-string
  " /chosen" (find-dev) if
    " bootargs" rot (property)
  then

  \ Execute platform-specific boot code, e.g. kernel
  s" platform-boot" $find if 
    execute		
  then

  (find-bootdevice)	\ Setup bootargs
  $load			\ load and go
  go
;


\ : diagnostic-mode?    ( -- diag? )
\   ;

\ : diag-switch?    ( -- diag? )
\   ;
