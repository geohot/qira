#!/bin/bash -e
cd pin

if [ ! -d pin-latest ]; then
  wget -O- http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.13-65163-gcc.4.4.7-linux.tar.gz | gunzip | tar x
  ln -s pin-2.13-65163-gcc.4.4.7-linux pin-latest
fi

# pin build deps, good?
sudo apt-get install gcc-multilib g++-multilib

# now we need capstone so the user can see assembly
wget -O /tmp/cs.deb http://www.capstone-engine.org/download/2.1.2/capstone-2.1.2_amd64.deb
sudo dpkg -i /tmp/cs.deb
rm /tmp/cs.deb

mkdir -p obj-ia32 obj-intel64
PIN_ROOT=./pin-latest make
PIN_ROOT=./pin-latest TARGET=ia32 make

