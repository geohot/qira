\ tag: FCode table setup
\ 
\ this code implements an fcode evaluator 
\ as described in IEEE 1275-1994
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 

hex

: undefined-fcode ." undefined fcode word." cr ;
: reserved-fcode  ." reserved fcode word."  cr ;

: ['], ( <word> -- )
  ' ,
;

: n['], ( n <word> -- )
  ' swap 0 do
    dup ,
  loop
  drop
;

\ the table used 
create fcode-master-table
  ['], end0
  f n['], reserved-fcode
  ['], b(lit)
  ['], b(')
  ['], b(")
  ['], bbranch
  ['], b?branch
  ['], b(loop)
  ['], b(+loop)
  ['], b(do)
  ['], b(?do)
  ['], i
  ['], j
  ['], b(leave)
  ['], b(of)
  ['], execute
  ['], +
  ['], -
  ['], *
  ['], /
  ['], mod
  ['], and
  ['], or
  ['], xor
  ['], invert
  ['], lshift
  ['], rshift
  ['], >>a
  ['], /mod
  ['], u/mod
  ['], negate
  ['], abs
  ['], min
  ['], max
  ['], >r
  ['], r>
  ['], r@
  ['], exit
  ['], 0=
  ['], 0<>
  ['], 0<
  ['], 0<=
  ['], 0>
  ['], 0>=
  ['], <
  ['], >
  ['], =
  ['], <>
  ['], u>
  ['], u<=
  ['], u<
  ['], u>=
  ['], >=
  ['], <=
  ['], between
  ['], within
  ['], drop
  ['], dup
  ['], over
  ['], swap
  ['], rot
  ['], -rot
  ['], tuck
  ['], nip
  ['], pick
  ['], roll
  ['], ?dup
  ['], depth
  ['], 2drop
  ['], 2dup
  ['], 2over
  ['], 2swap
  ['], 2rot
  ['], 2/
  ['], u2/
  ['], 2*
  ['], /c
  ['], /w
  ['], /l
  ['], /n
  ['], ca+
  ['], wa+
  ['], la+
  ['], na+
  ['], char+
  ['], wa1+
  ['], la1+
  ['], cell+
  ['], chars
  ['], /w*
  ['], /l*
  ['], cells
  ['], on
  ['], off
  ['], +!
  ['], @
  ['], l@
  ['], w@
  ['], <w@
  ['], c@
  ['], !
  ['], l!
  ['], w!
  ['], c!
  ['], 2@
  ['], 2!
  ['], move
  ['], fill
  ['], comp
  ['], noop
  ['], lwsplit
  ['], wljoin
  ['], lbsplit
  ['], bljoin
  ['], wbflip
  ['], upc
  ['], lcc
  ['], pack
  ['], count
  ['], body>
  ['], >body
  ['], fcode-revision
  ['], span
  ['], unloop
  ['], expect
  ['], alloc-mem
  ['], free-mem
  ['], key?
  ['], key
  ['], emit
  ['], type
  ['], (cr
  ['], cr
  ['], #out
  ['], #line
  ['], hold
  ['], <#
  ['], u#>
  ['], sign
  ['], u#
  ['], u#s
  ['], u.
  ['], u.r
  ['], .
  ['], .r
  ['], .s
  ['], base
  ['], convert                  \ reserved (compatibility)
  ['], $number
  ['], digit
  ['], -1
  ['], 0
  ['], 1
  ['], 2
  ['], 3
  ['], bl
  ['], bs
  ['], bell
  ['], bounds
  ['], here
  ['], aligned
  ['], wbsplit
  ['], bwjoin
  ['], b(<mark)
  ['], b(>resolve)
  ['], set-token-table
  ['], set-table
  ['], new-token
  ['], named-token
  ['], b(:)
  ['], b(value)
  ['], b(variable)
  ['], b(constant)
  ['], b(create)
  ['], b(defer)
  ['], b(buffer:)
  ['], b(field)
  ['], b(code)
  ['], instance
  ['], reserved-fcode
  ['], b(;)
  ['], b(to)
  ['], b(case)
  ['], b(endcase)
  ['], b(endof)
  ['], #
  ['], #s
  ['], #>
  ['], external-token
  ['], $find
  ['], offset16
  ['], evaluate
  ['], reserved-fcode
  ['], reserved-fcode
  ['], c,
  ['], w,
  ['], l,
  ['], ,
  ['], um*
  ['], um/mod
  ['], reserved-fcode
  ['], reserved-fcode
  ['], d+
  ['], d-
  ['], get-token
  ['], set-token
  ['], state
  ['], compile,
  ['], behavior
  11 n['], reserved-fcode
  ['], start0
  ['], start1
  ['], start2
  ['], start4
  8 n['], reserved-fcode
  ['], ferror
  ['], version1
  ['], 4-byte-id
  ['], end1
  ['], reserved-fcode
  ['], dma-alloc
  ['], my-address
  ['], my-space
  ['], memmap
  ['], free-virtual
  ['], >physical
  8 n['], reserved-fcode
  ['], my-params
  ['], property
  ['], encode-int
  ['], encode+
  ['], encode-phys
  ['], encode-string
  ['], encode-bytes
  ['], reg
  ['], intr
  ['], driver
  ['], model
  ['], device-type
  ['], parse-2int
  ['], is-install
  ['], is-remove
  ['], is-selftest
  ['], new-device
  ['], diagnostic-mode?
  ['], display-status
  ['], memory-test-suite
  ['], group-code
  ['], mask
  ['], get-msecs
  ['], ms
  ['], finish-device
  ['], decode-phys           \ 128
  ['], push-package
  ['], pop-package
  ['], interpose             \ extension (recommended practice)
  4 n['], reserved-fcode
  ['], map-low
  ['], sbus-intr>cpu
  1e n['], reserved-fcode
  ['], #lines
  ['], #columns
  ['], line#
  ['], column#
  ['], inverse?
  ['], inverse-screen?
  ['], frame-buffer-busy?
  ['], draw-character
  ['], reset-screen
  ['], toggle-cursor
  ['], erase-screen
  ['], blink-screen
  ['], invert-screen
  ['], insert-characters
  ['], delete-characters
  ['], insert-lines
  ['], delete-lines
  ['], draw-logo
  ['], frame-buffer-adr
  ['], screen-height
  ['], screen-width
  ['], window-top
  ['], window-left
  3 n['], reserved-fcode
  ['], default-font
  ['], set-font
  ['], char-height
  ['], char-width
  ['], >font
  ['], fontbytes
  10 n['], reserved-fcode             \ fb1 words
  ['], fb8-draw-character
  ['], fb8-reset-screen
  ['], fb8-toggle-cursor
  ['], fb8-erase-screen
  ['], fb8-blink-screen
  ['], fb8-invert-screen
  ['], fb8-insert-characters
  ['], fb8-delete-characters
  ['], fb8-insert-lines
  ['], fb8-delete-lines
  ['], fb8-draw-logo
  ['], fb8-install
  4 n['], reserved-fcode           \ reserved
  7 n['], reserved-fcode           \ VME-bus support
  9 n['], reserved-fcode           \ reserved
  ['], return-buffer
  ['], xmit-packet
  ['], poll-packet
  ['], reserved-fcode
  ['], mac-address
  5c n['], reserved-fcode          \ 1a5-200 reserved
  ['], device-name
  ['], my-args
  ['], my-self
  ['], find-package
  ['], open-package
  ['], close-package
  ['], find-method
  ['], call-package
  ['], $call-parent
  ['], my-parent
  ['], ihandle>phandle
  ['], reserved-fcode
  ['], my-unit
  ['], $call-method
  ['], $open-package
  ['], processor-type
  ['], firmware-version
  ['], fcode-version
  ['], alarm
  ['], (is-user-word)
  ['], suspend-fcode
  ['], abort
  ['], catch
  ['], throw
  ['], user-abort
  ['], get-my-property
  ['], decode-int
  ['], decode-string
  ['], get-inherited-property
  ['], delete-property
  ['], get-package-property
  ['], cpeek
  ['], wpeek
  ['], lpeek
  ['], cpoke
  ['], wpoke
  ['], lpoke
  ['], lwflip
  ['], lbflip
  ['], lbflips
  ['], adr-mask
  4 n['], reserved-fcode       \ 22a-22d
64bit? [IF]
  ['], (rx@)
  ['], (rx!)
[ELSE]
   2 n['], reserved-fcode       \ 22e-22f 
[THEN]
  ['], rb@
  ['], rb!
  ['], rw@
  ['], rw!
  ['], rl@
  ['], rl!
  ['], wbflips
  ['], lwflips
  ['], probe
  ['], probe-virtual
  ['], reserved-fcode
  ['], child
  ['], peer
  ['], next-property
  ['], byte-load
  ['], set-args
  ['], left-parse-string        \ 240
64bit? [IF]
  ['], bxjoin
  ['], <l@
  ['], lxjoin
  ['], wxjoin
  ['], x,
  ['], x@
  ['], x!
  ['], /x
  ['], /x*
\   ['], /xa+
\   ['], /xa1+
  ['], xbflip
  ['], xbflips
  ['], xbsplit
  ['], xlflip
  ['], xlflips
  ['], xlsplit
  ['], xwflip
  ['], xwflips
  ['], xwsplit
[ELSE]
  7 n['], reserved-fcode	\ 241-247 (Part of IEEE1275 64-bit draft standard)
  ['], /x
  c n['], reserved-fcode	\ 249-254 (Part of IEEE1275 64-bit draft standard)
[THEN]


here fcode-master-table - constant fcode-master-table-size


: nreserved ( fcode-table-ptr first last xt -- )
  -rot 1+ swap do
    2dup swap i cells + !
  loop
  2drop 
;

:noname
  800 cells alloc-mem to fcode-sys-table

  fcode-sys-table
  dup 0 5ff ['] reserved-fcode nreserved        \ built-in fcodes
  dup 600 7ff ['] undefined-fcode nreserved     \ vendor fcodes
  
  \ copy built-in fcodes
  fcode-master-table swap fcode-master-table-size move
; initializer

: (init-fcode-table) ( -- )
  fcode-sys-table fcode-table 800 cells move
  \ clear local fcodes
  fcode-table 800 fff ['] undefined-fcode nreserved
;

['] (init-fcode-table) to init-fcode-table
