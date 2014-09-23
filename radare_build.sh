#!/bin/sh
mkdir -p radare
cd radare

sudo apt-get install valac-0.22 libvala-0.22-dev

pushd .
git clone https://github.com/radare/valabind.git
make
sudo make install
popd

pushd .
git clone https://github.com/radare/radare2.git
cd radare2
./configure
make
sudo make install
sys/python.sh
popd




