#!/bin/sh
set -e

pushd .
cd ~/build/qemu
make -j32
popd

#rm -rf /tmp/qira*
~/build/qemu/i386-linux-user/qemu-i386 -singlestep $@
ls -l /tmp/qira*

