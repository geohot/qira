#!/bin/bash
set -e

# for building blist and stuff for flask like gevent

# we need pip to install python stuff
if [ $(which apt-get) ]; then
  echo "installing apt packagtes"
  sudo apt-get install build-essential python-dev python-pip
fi

echo "installing pip packages"
# pyelftools isn't needed anymore
sudo pip install blist flask-socketio

echo "making symlinks"
sudo ln -sf $(pwd)/qira /usr/local/bin/qira
sudo ln -sf $(pwd)/qemu/qira-i386 /usr/local/bin/qira-i386
sudo ln -sf $(pwd)/qemu/qira-arm /usr/local/bin/qira-arm
sudo ln -sf $(pwd)/qemu/qira-sparc /usr/local/bin/qira-sparc
sudo ln -sf $(pwd)/qemu/qira-sparc32plus /usr/local/bin/qira-sparc32plus
sudo ln -sf $(pwd)/qemu/qira-x86_64 /usr/local/bin/qira-x86_64

