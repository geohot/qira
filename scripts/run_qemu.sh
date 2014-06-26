#!/bin/sh
set -e

pushd .
cd ~/build/qemu
make -j32
popd

~/build/qemu/i386-linux-user/qemu-i386 -singlestep -d in_asm $1 2> /tmp/qira_disasm
ls -l /tmp/qira*

