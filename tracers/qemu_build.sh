#!/bin/bash

QEMU_VERSION=2.1.0-rc0

# if you don't have ubuntu you are on your own here
if [ $(which apt-get) ]; then
  echo "fetching qemu build-deps, enter your password"
  sudo apt-get update -qq
  sudo apt-get --no-install-recommends -qq -y build-dep qemu
  sudo apt-get install -qq -y wget flex bison libtool automake autoconf autotools-dev pkg-config libglib2.0-dev
else
  echo "WARNING: you don't have apt-get, you are required to fetch the build deps of QEMU on your own"
fi

# ok, strict mode
set -e

# get qemu if we don't have it
if [ ! -d qemu/qemu-latest ]; then
  rm -rf qemu
  mkdir -p qemu
  cd qemu
  wget http://wiki.qemu-project.org/download/qemu-$QEMU_VERSION.tar.bz2
  tar xf qemu-$QEMU_VERSION.tar.bz2
  ln -s qemu-$QEMU_VERSION qemu-latest

  ln -s qemu-latest/arm-linux-user/qemu-arm qira-arm
  ln -s qemu-latest/i386-linux-user/qemu-i386 qira-i386
  ln -s qemu-latest/x86_64-linux-user/qemu-x86_64 qira-x86_64
  ln -s qemu-latest/ppc-linux-user/qemu-ppc qira-ppc
  ln -s qemu-latest/aarch64-linux-user/qemu-aarch64 qira-aarch64
  ln -s qemu-latest/mips-linux-user/qemu-mips qira-mips

  cd qemu-latest
  patch -p1 < ../../qemu.patch
  cd ../..
fi

cd qemu/qemu-latest
./configure --target-list=i386-linux-user,x86_64-linux-user,arm-linux-user,ppc-linux-user,aarch64-linux-user,mips-linux-user --enable-tcg-interpreter --enable-debug-tcg --cpu=unknown --enable-tcg-interpreter --enable-debug-tcg --cpu=unknown
make -j $(grep processor < /proc/cpuinfo | wc -l)

