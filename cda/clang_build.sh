#!/bin/bash -e
sudo pip install html

mkdir -p clang-latest
cd clang-latest
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
rm -f ../clang
ln -s clang-latest/llvm/tools/clang/bindings/python/clang ../clang
rm -f ../include
ln -s clang-latest/cfe-3.4.2.src/lib/Headers ../include

# don't actually build clang because it takes forever and sucks
exit 0

mkdir -p build
cd build
../llvm/configure --enable-optimized
make -j $(grep processor < /proc/cpuinfo | wc -l)

