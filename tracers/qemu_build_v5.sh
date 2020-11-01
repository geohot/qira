#!/bin/bash -e

if [ ! -d qemu/qemu ]; then
  cd qemu
  git clone https://github.com/korniltsev/qemu.git --depth 1 --branch qira_5.2
  cd ..
fi

cd qemu/qemu
./configure --target-list=i386-linux-user,x86_64-linux-user,arm-linux-user,ppc-linux-user,aarch64-linux-user,mips-linux-user,mipsel-linux-user \
    --enable-tcg-interpreter \
    --enable-debug-tcg       \
    --cpu=x86_64             \
    --enable-capstone        \
    --python=python3
make -j$(getconf _NPROCESSORS_ONLN) 
