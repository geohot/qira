#!/bin/bash -e
sudo pip install html

mkdir -p clang
cd clang
if [ ! -f .downloaded_clang ]; then
  echo "downloading"
  wget http://llvm.org/releases/3.4.2/cfe-3.4.2.src.tar.gz
  wget http://llvm.org/releases/3.4/compiler-rt-3.4.src.tar.gz
  wget http://llvm.org/releases/3.4.2/llvm-3.4.2.src.tar.gz
  touch .downloaded_clang
fi

echo "extracting"
tar xf llvm-3.4.2.src.tar.gz
tar xf cfe-3.4.2.src.tar.gz
tar xf compiler-rt-3.4.src.tar.gz

echo "making symlinks"
ln -sf llvm-3.4.2.src llvm
ln -sf ../../cfe-3.4.2.src llvm/tools/clang
ln -sf ../../compiler-rt-3.4 llvm/projects/compiler-rt

mkdir -p build
cd build
../llvm/configure
make -j

