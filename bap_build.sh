#!/bin/bash -e

# this script is woefully incomplete
# because I already had tons of stuff on this VM
# update before release

sudo apt-get install ocaml-interp

mkdir -p bap
cd bap
if [ ! -d bap-lifter ]; then
  git clone https://github.com/BinaryAnalysisPlatform/bap-lifter.git
fi

cd bap-lifter
./configure
make -j $(grep processor < /proc/cpuinfo | wc -l)

# installed at bap/bap-lifter/toil.native

