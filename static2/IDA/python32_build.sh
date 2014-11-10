#!/bin/bash -e

# also install deps for ida
sudo dpkg --add-architecture i386
sudo apt-get update
# libssl-dev:i386 is broken and does things like uninstall g++, but they seem to come back ok
sudo apt-get install libssl-dev:i386
# and the rest
sudo apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386 libglib2.0-0:i386 libfreetype6:i386 libsm6:i386 libxrender1:i386 libfontconfig1:i386 libxext-dev:i386 g++-multilib libssl1.0.0:i386

mkdir -p python32
cd python32
if [ ! -d Python ]; then
  wget https://www.python.org/ftp/python/2.7.8/Python-2.7.8.tar.xz
  tar xvf Python-2.7.8.tar.xz
  ln -s Python-2.7.8 Python
fi

cd Python
LDFLAGS="-m32" CFLAGS="-m32" ./configure
make -j $(grep processor < /proc/cpuinfo | wc -l)

