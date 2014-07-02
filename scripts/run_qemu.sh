#!/bin/bash
set -e

pushd .
cd ../qemu/qemu-latest/
make -j32
popd

#rm -rf /tmp/qira*
#../qemu/qemu-latest/i386-linux-user/qemu-i386 -singlestep -d in_asm $@ 2> /tmp/qira_disasm
../qemu/qemu-latest/i386-linux-user/qemu-i386 -singlestep $@
ls -l /tmp/qira*

