#!/bin/sh
set -e

pushd .
cd ~/build/qemu
make -j32
popd

#~/build/qemu/i386-linux-user/qemu-i386 -singlestep -strace -d in_asm ~/tmp/hello
#echo "4t_l34st_it_was_1mperat1v3..." | ~/build/qemu/i386-linux-user/qemu-i386 -singlestep -d in_asm ~/tmp/ctf/hudak 2> /tmp/qira_disasm
#~/build/qemu/i386-linux-user/qemu-i386 -singlestep -d in_asm ../tests/a.out 2> /tmp/qira_disasm
~/build/qemu/i386-linux-user/qemu-i386 -singlestep -d in_asm $1 2> /tmp/qira_disasm
ls -l /tmp/qira*

