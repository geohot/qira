#!/bin/bash -e

rm -rf distrib/
mkdir -p distrib/qira

QEMU_SOURCE=1
QEMU_BINARIES=1
VERSION=$(cat VERSION)
echo "packaging version $VERSION"

# VERSION is required to build the python thing
echo "copying docs"
cp -av VERSION README.md distrib/qira/

# requires objdump
# writable /tmp

# aim for a 2mb distributable
# 100kb for the python, 100kb for the web, 200kb for the ida plugin(static), 1mb for qira-qemu
# +the meteor install size
# consider smaller packaging for the python

# hmm can we package as a .deb for ubuntu?

# perhaps instead of this bundle we just install meteor
# curl https://install.meteor.com | /bin/sh
# or preship this file in the tarball?
# the advantage of this over the bundle is it ships mongo
echo "copying webapp"
cp -R web distrib/qira/
#rm -rf distrib/qira/web/.meteor/local
#rm -f distrib/qira/web/qira.html   # this doesn't work to change, so don't allow the user to
#mrt bundle ../bin/qira_web.tar.gz
#cp -R webstatic distrib/qira/

# sudo apt-get install python-pip
# sudo pip install pymongo
echo "copying middleware"
mkdir -p distrib/qira/middleware
cp -av middleware/*.py distrib/qira/middleware/

# static2
echo "copying static2"
mkdir -p distrib/qira/static2
pyclean static2/
cp -av static2/* distrib/qira/static2/

# built for ida 6.6
# perhaps build for older IDA as well, ie 6.1
# and mac + windows
# fairly standard deps + libcrypto, libssl, libz and libida
mkdir -p distrib/qira/ida/bin
echo "copying ida plugin"
cp -av ida/bin/* distrib/qira/ida/bin/

echo "copying qemu source build scripts"
if [ $QEMU_SOURCE ]; then
  mkdir -p distrib/qira/tracers
  cp -av tracers/qemu.patch tracers/qemu_build.sh distrib/qira/tracers
fi

if [ $QEMU_BINARIES ]; then
  # fairly standard deps + librt, libglib, libpcre
  echo "copying qemu"
  mkdir -p distrib/qira/tracers/qemu
  for arch in "i386" "arm" "x86_64" "ppc" "aarch64" "mips" "mipsel"; do
    cp -v "tracers/qemu/qira-$arch" "distrib/qira/tracers/qemu/qira-$arch"
    strip "distrib/qira/tracers/qemu/qira-$arch"
    #upx -9 "distrib/qira/qemu/qira-$arch"
  done
fi

echo "copying qiradb"
mkdir -p distrib/qira/qiradb
cp -Rav qiradb/* distrib/qira/qiradb/

echo "copying pin"
mkdir -p distrib/qira/tracers/pin
cp -av tracers/pin_build.sh distrib/qira/tracers
cp -av tracers/pin/makefile tracers/pin/qirapin.cpp distrib/qira/tracers/pin/
mkdir -p distrib/qira/tracers/pin/strace
cp -av tracers/pin/strace/*.h distrib/qira/tracers/pin/strace/

#echo "copying cda"
#mkdir -p distrib/qira/cda distrib/qira/cda/clang
#cp -av cda/*.py distrib/qira/cda/
#cp -av cda/clang/*.py distrib/qira/cda/clang/
#cp -Rav cda/static distrib/qira/cda/
#cp -av cda_build.sh distrib/qira/

# package up the python, hopefully this includes pymongo driver
# hmm, it doesn't, user will need to install
#cd bin
#rm -rf qira_middleware
#mkdir -p qira_middleware
#cd qira_middleware
#~/build/PyInstaller-2.1/pyinstaller.py ../../scripts/qira_middleware.py
#cd dist/qira_middleware
#tar zcvf ../../../qira_middleware.tar.gz *
#cd ../../
#cd ../../

# *** startup ***
# the meteor and the middleware should always be running(fix the hang bug)
# launch both in upscript with qira-server in one window. make the teardown nice
# then you run qira-i386 <binary>, we need to hack in the -singlestep arg

echo "copying binaries"
cp -av requirements.txt install.sh qira fetchlibs.sh distrib/qira/

echo "making archive"
cd distrib/
tar cvf qira-$VERSION.tar qira
xz qira-$VERSION.tar
cd ../

sha1sum distrib/qira-$VERSION.tar.xz

