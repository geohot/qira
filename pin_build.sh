#!/bin/bash -e
cd pin

unamestr=$(uname)
if [[ "$unamestr" == 'Linux' ]]; then
  if [ ! -d pin-latest ]; then
    wget -O- http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-67254-gcc.4.4.7-linux.tar.gz | gunzip | tar x
    ln -s pin-2.14-67254-gcc.4.4.7-linux pin-latest
  fi

  if [ ! -f /usr/lib/libcapstone.so ]; then
    # pin build deps, good?
    sudo apt-get install gcc-multilib g++-multilib

    # now we need capstone so the user can see assembly
    wget -O /tmp/cs.deb http://www.capstone-engine.org/download/2.1.2/capstone-2.1.2_amd64.deb
    sudo dpkg -i /tmp/cs.deb
    rm /tmp/cs.deb
  fi
elif [[ "$unamestr" == 'Darwin' ]]; then
  if [ ! -d pin-latest ]; then
    wget -O- http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-67254-clang.5.1-mac.tar.gz | gunzip | tar x
    ln -s pin-2.14-67254-clang.5.1-mac pin-latest
  fi
  
fi


mkdir -p obj-ia32 obj-intel64
PIN_ROOT=./pin-latest make
PIN_ROOT=./pin-latest TARGET=ia32 make

