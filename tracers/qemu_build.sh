#!/bin/bash

QEMU_VERSION=2.1.3

#hardcoded to 2.1.3 for now
QEMU_SHA256="9b68fd0e6f6c401939bd1c9c6ab7052d84962007bb02919623474e9269f60a40"

python="python"
# if you don't have ubuntu you are on your own here
if [ $(which apt-get) ]; then
  echo "fetching qemu build-deps, enter your password"
  sudo apt-get update -qq
  sudo apt-get --no-install-recommends -qq -y build-dep qemu
  sudo apt-get install -qq -y wget flex bison libtool automake autoconf autotools-dev pkg-config libglib2.0-dev
elif [ $(which pacman) ]; then
  python="python2"
  echo "WARNING: you are using pacman, you are awesome but are going to need to fetch the build deps of QEMU on your own"
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

  HASH=`sha256sum ./qemu-"$QEMU_VERSION".tar.bz2 2>/dev/null | cut -d' ' -f1`
<<<<<<< HEAD
=======

>>>>>>> 55078b2deb6730d383eef04beb9baf5f38076900
  if [ "$HASH" != "$QEMU_SHA256" ]; then
    echo "Error: qemu-"$QEMU_VERSION".tar.bz2 has an invalid checksum."
    exit 1
  fi

  tar xf qemu-$QEMU_VERSION.tar.bz2
  ln -s qemu-$QEMU_VERSION qemu-latest

  ln -s qemu-latest/arm-linux-user/qemu-arm qira-arm
  ln -s qemu-latest/i386-linux-user/qemu-i386 qira-i386
  ln -s qemu-latest/x86_64-linux-user/qemu-x86_64 qira-x86_64
  ln -s qemu-latest/ppc-linux-user/qemu-ppc qira-ppc
  ln -s qemu-latest/aarch64-linux-user/qemu-aarch64 qira-aarch64
  ln -s qemu-latest/mips-linux-user/qemu-mips qira-mips
  ln -s qemu-latest/mipsel-linux-user/qemu-mipsel qira-mipsel

  cd qemu-latest
  patch -p1 < ../../qemu.patch
  cd ../..
fi

cd qemu/qemu-latest
./configure --target-list=i386-linux-user,x86_64-linux-user,arm-linux-user,ppc-linux-user,aarch64-linux-user,mips-linux-user,mipsel-linux-user --enable-tcg-interpreter --enable-debug-tcg --cpu=unknown --enable-tcg-interpreter --enable-debug-tcg --cpu=unknown --python="$python"
make -j $(grep processor < /proc/cpuinfo | wc -l)
