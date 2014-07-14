#!/bin/bash
set -e

# we need pip to install python stuff
if [ ! $(which pip) ]; then
  echo "installing pip"
  sudo apt-get install python-pip
fi
echo "installing pip packages"

# pymongo isn't really needed anymore
sudo pip install pyelftools blist flask-socketio

echo "making symlinks"
sudo ln -sf $(pwd)/qira /usr/local/bin/qira
sudo ln -sf $(pwd)/qira-server /usr/local/bin/qira-server
sudo ln -sf $(pwd)/qemu/qira-i386 /usr/local/bin/qira-i386
sudo ln -sf $(pwd)/qemu/qira-arm /usr/local/bin/qira-arm

