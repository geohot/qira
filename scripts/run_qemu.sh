#!/bin/bash
set -e

pushd .
cd ../qemu/qemu-2.0.0/
make -j32
popd

#rm -rf /tmp/qira*
../qemu/qemu-2.0.0/i386-linux-user/qemu-i386 -singlestep -d in_asm $@ 2> /tmp/qira_disasm
ls -l /tmp/qira*

