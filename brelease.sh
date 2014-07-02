#!/bin/bash
#rm -rf bin/
#mkdir -p bin/

# requires objdump
# sudo apt-get install python-pip
# sudo pip install pymongo
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
cd web
echo "bundling webapp"
#mrt bundle ../bin/qira_web.tar.gz
cd ../

# built for ida 6.6
# perhaps build for older IDA as well, ie 6.1
# and mac + windows
# fairly standard deps + libcrypto, libssl, libz and libida
cd ida_plugin
echo "building ida plugin"
./build.sh
cp qira.plx ../bin/qira_ida66_linux.plx
strip ../bin/qira_ida66_linux.plx
cd ../

# fairly standard deps + librt, libglib, libpcre
echo "copying qemu"
cp qemu/qemu-latest/i386-linux-user/qemu-i386 bin/qira-i386
strip bin/qira-i386

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

