include config.fs

\ -------------------------------------------------------------------------
\ registers 
\ -------------------------------------------------------------------------

0 value %cr
0 value %ctr
0 value %lr
0 value %msr
0 value %srr0
0 value %srr1
0 value %pc							\ should be an alias for %srr0

0 value %r0
0 value %r1
0 value %r2
0 value %r3
0 value %r4
0 value %r5
0 value %r6
0 value %r7
0 value %r8
0 value %r9
0 value %r10
0 value %r11
0 value %r12
0 value %r13
0 value %r14
0 value %r15
0 value %r16
0 value %r17
0 value %r18
0 value %r19
0 value %r20
0 value %r21
0 value %r22
0 value %r23
0 value %r24
0 value %r25
0 value %r26
0 value %r27
0 value %r28
0 value %r29
0 value %r30
0 value %r31

0 value %xer
0 value %sprg0
0 value %sprg1
0 value %sprg2
0 value %sprg3

\ -------------------------------------------------------------------------
\ Load VGA FCode driver blob
\ -------------------------------------------------------------------------

[IFDEF] CONFIG_DRIVER_VGA
  -1 value vga-driver-fcode
  " QEMU,VGA.bin" $encode-file to vga-driver-fcode
[THEN]

\ -------------------------------------------------------------------------
\ other
\ -------------------------------------------------------------------------

\ Set by BootX when booting Mac OS X
defer spin
