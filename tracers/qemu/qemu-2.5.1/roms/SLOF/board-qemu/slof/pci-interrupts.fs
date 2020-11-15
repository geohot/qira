
: pci-gen-irq-map-one ( prop-addr prop-len slot pin -- prop-addr prop-len )
        2dup + 4 mod                ( prop-addr prop-len slot pin parentpin )
        >r >r                       ( prop-addr prop-len slot R: swizzledpin pin )

        \ Child slot#
        B lshift encode-int+        ( prop-addr prop-len R: swizzledpin pin )
        \ Child 64bit BAR (not really used)
        0 encode-64+
        \ Chile pin#
        r> encode-int+              ( prop-addr prop-len R: swizzledpin )

        \ Parent phandle
        get-parent encode-int+

        \ Parent slot#
        get-node >space
        pci-addr2dev B lshift       ( prop-addr prop-len parent-slot R: swizzledpin )
        encode-int+
        \ Parent 64bit BAR (not really used)
        0 encode-64+
        \ Parent pin
        r> encode-int+              ( prop-addr prop-len R: )
;

: pci-gen-irq-entry ( prop-addr prop-len config-addr -- prop-addr prop-len )
        pci-addr2dev 4 mod          ( prop-addr prop-len slot )
        -rot                        ( slot prop-addr prop-len )
        5 1 DO
                2 pick i            ( slot prop-addr prop-len slot pin )
                pci-gen-irq-map-one
        LOOP
        rot drop
;

: pci-set-irq-line ( config-addr -- )
  drop
;
