\ Set up all known capabilities for this board to the plugged devices

: pci-msi-prop ( addr -- )
    5 pci-cap-find          ( capaddr )
    ?dup IF
        2+ rtas-config-w@   ( msi-control )
        1 rshift 7 and      ( msi-control:3:1 )

        dup 6 < IF
            1 swap lshift   ( vectors# )
            encode-int " ibm,req#msi" property
        ELSE
            ." Invalid MSI vectors number " . cr
        THEN
    THEN
;

: pci-msix-prop ( addr -- )
    11 pci-cap-find         ( capaddr )
    ?dup IF
        2+ rtas-config-w@   ( msix-control )
        7ff and             ( msix-control:10:0 )
        1+                  ( vectors# )
        ?dup IF
            encode-int " ibm,req#msi-x" property
        THEN
    THEN
;

: pci-set-capabilities ( config-addr -- )
    dup pci-msi-prop
    dup pci-msix-prop
    drop
;
