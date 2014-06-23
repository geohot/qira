#!/bin/sh
set -e

nasm -f elf jmpbug.asm
gcc -m32 jmpbug.o -o a.out -nostartfiles -nostdlib -nodefaultlibs

