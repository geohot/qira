#!/bin/sh
set -e

nasm -f elf64 $1.asm
gcc $1.o -o a.out -nostartfiles -nostdlib -nodefaultlibs

