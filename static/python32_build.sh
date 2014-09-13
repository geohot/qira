#!/bin/bash -e

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

