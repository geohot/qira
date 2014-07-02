#!/bin/bash
rm -rf qemu
mkdir -p qemu
cd qemu
wget http://wiki.qemu-project.org/download/qemu-2.0.0.tar.bz2
tar xf qemu-2.0.0.tar.bz2
cd qemu-2.0.0
mv tci.c tci.c.bak
ln -s ../../qemu_mods/tci.c tci.c
./configure --target-list=i386-linux-user
make -j32

