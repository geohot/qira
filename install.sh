#!/bin/bash -e

# default is just pip, but on things like arch where python 3 is default, it's pip2
PIP="pip"

# we need pip to install python stuff
# build for building qiradb and stuff for flask like gevent
if [ $(which apt-get) ]; then
  echo "installing apt packages"
  sudo apt-get install build-essential python-dev python-pip debootstrap libjpeg-dev zlib1g-dev unzip
elif [ $(which pacman) ]; then
  echo "installing pip"
  sudo pacman -S base-devel python2-pip
  PIP="pip2"
elif [ $(which yum) ]; then
  sudo yum install python-pip python-devel gcc gcc-c++
fi

if [ $(qemu/qira-i386 > /dev/null; echo $?) == 1 ]; then
  echo "QIRA QEMU appears to run okay"
else
  echo "building QEMU"
  ./qemu_build.sh
fi

echo "installing pip packages"
# we install more than we strictly need here, because pip is so easy
sudo $PIP install --upgrade html flask-socketio pillow pyelftools socketIO-client pydot ipaddr capstone ./qiradb

echo "making symlink"
sudo ln -sf $(pwd)/qira /usr/local/bin/qira

# meteor is removed :)

