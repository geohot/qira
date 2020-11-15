#!/bin/sh
# Script to test if the build works properly.

# Test IASL is installed.
$IASL -h > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "The SeaBIOS project requires the 'iasl' package be installed." >&2
    echo "Many Linux distributions have this package." >&2
    echo "Try: sudo yum install iasl" >&2
    echo "Or: sudo apt-get install iasl" >&2
    echo "" >&2
    echo "Please install iasl and retry." >&2
    echo -1
    exit 0
fi

mkdir -p ${OUT}
TMPFILE1=${OUT}/tmp_testcompile1.c
TMPFILE1o=${OUT}/tmp_testcompile1.o
TMPFILE1_ld=${OUT}/tmp_testcompile1.lds
TMPFILE2=${OUT}/tmp_testcompile2.c
TMPFILE2o=${OUT}/tmp_testcompile2.o
TMPFILE3o=${OUT}/tmp_testcompile3.o

# Test if ld's alignment handling is correct.  This is a known problem
# with the linker that ships with Ubuntu 11.04.
cat - > $TMPFILE1 <<EOF
const char v1[] __attribute__((section(".text.v1"))) = "0123456789";
const char v2[] __attribute__((section(".text.v2"))) = "0123456789";
EOF
cat - > $TMPFILE1_ld <<EOF
SECTIONS
{
     .mysection 0x88f0 : {
. = 0x10 ;
*(.text.v1)
. = 0x20 ;
*(.text.v2)
. = 0x30 ;
     }
}
EOF
$CC -O -g -c $TMPFILE1 -o $TMPFILE1o > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Unable to execute the C compiler ($CC)." >&2
    echo "" >&2
    echo "Please install a working compiler and retry." >&2
    echo -1
    exit 0
fi
$LD -T $TMPFILE1_ld $TMPFILE1o -o $TMPFILE2o > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "The version of LD on this system ($LD) does not properly handle" >&2
    echo "alignments.  As a result, this project can not be built." >&2
    echo "" >&2
    echo "The problem may be the result of this LD bug report:" >&2
    echo " http://sourceware.org/bugzilla/show_bug.cgi?id=12726" >&2
    echo "" >&2
    echo "Please update to a working version of binutils and retry." >&2
    echo -1
    exit 0
fi

# Test for "-fwhole-program".  Older versions of gcc (pre v4.1) don't
# support the whole-program optimization - detect that.
$CC -fwhole-program -S -o /dev/null -xc /dev/null > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "  Working around no -fwhole-program" >&2
    echo 2
    exit 0
fi

# Test if "visible" variables and functions are marked global.  On
# OpenSuse 10.3 "visible" variables declared with "extern" first
# aren't marked as global in the resulting assembler.  On Ubuntu 7.10
# "visible" functions aren't marked as global in the resulting
# assembler.
cat - > $TMPFILE1 <<EOF
void __attribute__((externally_visible)) t1() { }
extern unsigned char v1;
unsigned char v1 __attribute__((section(".data16.foo.19"))) __attribute__((externally_visible));
EOF
$CC -Os -c -fwhole-program $TMPFILE1 -o $TMPFILE1o > /dev/null 2>&1
cat - > $TMPFILE2 <<EOF
void t1();
extern unsigned char v1;
int __attribute__((externally_visible)) main() { t1(); return v1; }
EOF
$CC -Os -c -fwhole-program $TMPFILE2 -o $TMPFILE2o > /dev/null 2>&1
$CC -nostdlib -Os $TMPFILE1o $TMPFILE2o -o $TMPFILE3o > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "  Working around non-functional -fwhole-program" >&2
    echo 2
    exit 0
fi

echo 0

# Also, the Ubuntu 8.04 compiler has a bug causing corruption when the
# "ebp" register is clobberred in an "asm" statement.  The code has
# been modified to not clobber "ebp" - no test is available yet.

rm -f $TMPFILE1 $TMPFILE1o $TMPFILE1_ld $TMPFILE2 $TMPFILE2o $TMPFILE3o
