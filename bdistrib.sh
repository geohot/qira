#!/bin/bash
set -e
rm -rf distrib/
mkdir -p distrib/

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
cp -R web distrib/
rm -rf web/.meteor/local
#mrt bundle ../bin/qira_web.tar.gz

# sudo apt-get install python-pip
# sudo pip install pymongo
echo "copying middleware"
mkdir -p distrib/middleware
cp middleware/*.py distrib/middleware/

# built for ida 6.6
# perhaps build for older IDA as well, ie 6.1
# and mac + windows
# fairly standard deps + libcrypto, libssl, libz and libida
mkdir -p distrib/ida
cd ida_plugin
echo "building ida plugin"
./build.sh
cp qira.plx ../distrib/ida/qira_ida66_linux.plx
strip ../distrib/ida/qira_ida66_linux.plx
cd ../

# fairly standard deps + librt, libglib, libpcre
echo "copying qemu"
mkdir -p distrib/qemu
cp qemu/qemu-latest/i386-linux-user/qemu-i386 distrib/qemu/qira-i386
strip distrib/qemu/qira-i386

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
cp qira distrib/
cp qira-server distrib/

