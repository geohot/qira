#!/bin/bash -e

# this script is woefully incomplete
# because I already had tons of stuff on this VM
# update before release

pushd .
cd /tmp
wget https://bootstrap.pypa.io/get-pip.py
sudo python get-pip.py
popd

sudo apt-get install libgmp-dev m4 ocaml-interp libpqxx-3.1 libpqxx3-dev glogg python-dev postgresql-server-dev-9.3 g++-4.8 gcc-4.8 ocaml-findlib opam camlp4-extra cmake
opam init
opam install piqi zarith core_kernel

mkdir -p bap
cd bap

if [ ! -d capnproto ]; then
  pushd .
  git clone https://github.com/kentonv/capnproto.git
  cd capnproto/c++
  ./setup-autotools.sh
  autoreconf -i && ./configure && make -j6 check && sudo make install
  popd
fi

sudo pip install -U cython
sudo pip install pycapnp

if [ ! -d bap-types ]; then
  pushd .
  git clone https://github.com/BinaryAnalysisPlatform/bap-types.git

  cd bap-types
  ./configure
  make -j $(grep processor < /proc/cpuinfo | wc -l)
  make install

  popd
fi

if [ ! -d llvm ]; then
  pushd .
  #wget http://ftp.de.debian.org/debian/pool/main/l/llvm-toolchain-snapshot/llvm-toolchain-snapshot_3.6~svn215195.orig.tar.bz2
  #tar xvf llvm-toolchain-snapshot_3.6~svn215195.orig.tar.bz2
  #mv llvm-toolchain-snapshot_3.6~svn215195 llvm
  #cd llvm
  git clone https://github.com/llvm-mirror/llvm.git
  cd llvm
  git checkout 0914f63cc3ce62b6872e2760dd325829b52d8396
  patch -f -p1 < ../../extra/llvmpatch/c-disasm-mcinst
  popd
fi

if [ ! -d llvm-build ]; then
  pushd .
  mkdir llvm-build
  cd llvm-build
  ../llvm/configure --enable-optimized --disable-assertions
  make -j $(grep processor < /proc/cpuinfo | wc -l)

  # clobber the system llvm
  sudo make install
  popd
fi

if [ ! -d llvm-mc ]; then
  pushd .
  git clone https://github.com/BinaryAnalysisPlatform/llvm-mc.git
  cd llvm-mc

  ./configure
  make -j $(grep processor < /proc/cpuinfo | wc -l)
  make install
  popd
fi

if [ ! -d bap-lifter ]; then
  pushd .
  git clone https://github.com/BinaryAnalysisPlatform/bap-lifter.git

  cd bap-lifter
  ./configure
  make -j $(grep processor < /proc/cpuinfo | wc -l)
  make install

  popd
fi

# below this line is broken

if [ ! -d holmes ]; then
  pushd .
  git clone https://github.com/BinaryAnalysisPlatform/holmes.git

  cd holmes
  mkdir build && cd build
  cmake -DCMAKE_CXX_COMPILER=g++-4.8 ..
  make

  popd
fi

if [ ! -d bap-container ]; then
  git clone https://github.com/BinaryAnalysisPlatform/bap-container.git

  cd bap-container
  mkdir build && cd build
  cmake -DCMAKE_CXX_COMPILER=g++-4.8 ..
  make
fi

# installed at bap/bap-lifter/toil.native

