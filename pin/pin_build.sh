#!/bin/bash -e
if [ ! -d pin-latest ]; then
  wget -O- http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.13-65163-gcc.4.4.7-linux.tar.gz | gunzip | tar x
  ln -s pin-2.13-65163-gcc.4.4.7-linux pin-latest
fi

PIN_ROOT=./pin-latest make
PIN_ROOT=./pin-latest TARGET=ia32 make

