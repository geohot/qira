#!/bin/bash
VERSION=qira-0.1

set -e
rm -rf distrib/
mkdir -p distrib/qira

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
rm -rf distrib/qira/web/.meteor/local
rm -f distrib/qira/web/qira.html   # this doesn't work to change, no don't allow the user to
#mrt bundle ../bin/qira_web.tar.gz
cp -R webstatic distrib/qira/

# sudo apt-get install python-pip
# sudo pip install pymongo
echo "copying middleware"
mkdir -p distrib/qira/middleware
cp middleware/*.py distrib/qira/middleware/

# built for ida 6.6
# perhaps build for older IDA as well, ie 6.1
# and mac + windows
# fairly standard deps + libcrypto, libssl, libz and libida
mkdir -p distrib/qira/ida/bin
echo "copying ida plugin"
cp ida/bin/* distrib/qira/ida/bin/

# fairly standard deps + librt, libglib, libpcre
echo "copying qemu"
mkdir -p distrib/qira/qemu
for arch in "i386" "arm" "x86_64"; do
  cp "qemu/qira-$arch" "distrib/qira/qemu/qira-$arch"
  strip "distrib/qira/qemu/qira-$arch"
  #upx -9 "distrib/qira/qemu/qira-$arch"
done

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
cp -av install.sh qira distrib/qira/

echo "making archive"
cd distrib/
#tar zcvf qira-0.3.tar.gz qira
tar cvf qira-0.3.tar qira
xz qira-0.3.tar
cd ../

