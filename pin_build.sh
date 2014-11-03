#!/bin/bash -e
cd pin

unamestr=$(uname)
if [[ "$unamestr" == 'Linux' ]]; then
  if [ ! -d pin-latest ]; then
    wget -O- http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-67254-gcc.4.4.7-linux.tar.gz | gunzip | tar x
    ln -s pin-2.14-67254-gcc.4.4.7-linux pin-latest
  fi

  # pin build deps, good?
  if [ $(which apt-get) ]; then
    echo "fetching pin tool building deps, enter your password"
    sudo apt-get install gcc-multilib g++-multilib
  else
    echo "WARNING: you don't have apt-get, you are required to fetch pin tool building deps (e.g. 32 bit libs) on your own"
  fi
elif [[ "$unamestr" == 'Darwin' ]]; then
  if [ ! -d pin-latest ]; then
    wget -O- http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-67254-clang.5.1-mac.tar.gz | gunzip | tar x
    ln -s pin-2.14-67254-clang.5.1-mac pin-latest
  fi
  
  # install capstone from dmg @ http://www.capstone-engine.org/download.html
fi


mkdir -p obj-ia32 obj-intel64
PIN_ROOT=./pin-latest make
PIN_ROOT=./pin-latest TARGET=ia32 make

