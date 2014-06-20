#!/bin/sh
set -e

pushd .
cd ~/build/qemu
make -j32
popd

~/build/qemu/i386-linux-user/qemu-i386 -singlestep -strace -d in_asm ~/tmp/hello

