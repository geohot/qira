#!/bin/sh
# Extract definitions from an assembler file.  This is based on code
# from the Linux Kernel.
INFILE=$1
OUTFILE=$2
cat > "$OUTFILE" <<EOF
// This is an auto-generated file.  DO NOT EDIT!
// Generated with "$0 $@"
#ifndef __ASM_OFFSETS_H
#define __ASM_OFFSETS_H
EOF
sed -ne "/^->/{s:->#\(.*\):/* \1 */:; \
        s:^->\([^ ]*\) [\$\#]*\([^ ]*\) \(.*\):#define \1 \2 /* \3 */:; \
        s:->::; p;}" < "$INFILE" >> "$OUTFILE"
cat >> "$OUTFILE" <<EOF
#endif // asm-offsets.h
EOF
