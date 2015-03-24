#!/bin/bash -e

wget http://wiki.qemu-project.org/download/qemu-2.1.0-rc0.tar.bz2
tar xf qemu-2.1.0-rc0.tar.bz2
cp -r qemu-2.1.0-rc0 qemu-2.1.0-rc0-patch
cp tci.c qemu-2.1.0-rc0-patch/tci.c
cp disas.c qemu-2.1.0-rc0-patch/disas.c
cp qemu.h qemu-2.1.0-rc0-patch/linux-user/qemu.h
cp main.c qemu-2.1.0-rc0-patch/linux-user/main.c
cp strace.c qemu-2.1.0-rc0-patch/linux-user/strace.c
cp strace.list qemu-2.1.0-rc0-patch/linux-user/strace.list
diff -rupN qemu-2.1.0-rc0 qemu-2.1.0-rc0-patch > out.patch
