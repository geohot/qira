#!/bin/sh
set -e

nasm -f elf $1.asm
gcc -m32 $1.o -o a.out -nostartfiles -nostdlib -nodefaultlibs

