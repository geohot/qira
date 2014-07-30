#!/bin/bash -e

if [ ! -d qemu/qemu-latest ]; then
  rm -rf qemu
  mkdir -p qemu
  cd qemu
  wget http://wiki.qemu-project.org/download/qemu-2.1.0-rc0.tar.bz2
  tar xf qemu-2.1.0-rc0.tar.bz2
  ln -s qemu-2.1.0-rc0 qemu-latest

  ln -s qemu-latest/arm-linux-user/qemu-arm qira-arm
  ln -s qemu-latest/i386-linux-user/qemu-i386 qira-i386
  ln -s qemu-latest/x86_64-linux-user/qemu-x86_64 qira-x86_64
  ln -s qemu-latest/ppc-linux-user/qemu-ppc qira-ppc

  cd qemu-latest
  mv tci.c tci.c.bak
  mv disas.c disas.c.bak
  mv linux-user/qemu.h linux-user/qemu.h.bak
  mv linux-user/main.c linux-user/main.c.bak
  mv linux-user/strace.c linux-user/strace.c.bak
  cd ../../

  if [ $(which apt-get) ]; then
    echo "fetching qemu build-deps, enter your password"
    sudo apt-get --no-install-recommends -y build-dep qemu
  fi
fi

cd qemu/qemu-latest
ln -sf ../../qemu_mods/tci.c tci.c
ln -sf ../../qemu_mods/disas.c disas.c
ln -sf ../../../qemu_mods/qemu.h linux-user/qemu.h
ln -sf ../../../qemu_mods/main.c linux-user/main.c
ln -sf ../../../qemu_mods/strace.c linux-user/strace.c
#./configure --target-list=i386-linux-user,arm-linux-user,x86_64-linux-user,sparc-linux-user,sparc32plus-linux-user --enable-tcg-interpreter --enable-debug-tcg --cpu=unknown
./configure --target-list=i386-linux-user,x86_64-linux-user,arm-linux-user,ppc-linux-user --enable-tcg-interpreter --enable-debug-tcg --cpu=unknown
make -j32


