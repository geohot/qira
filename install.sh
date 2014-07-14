#!/bin/bash
set -e

# we need pymongo
if [ ! $(which pip) ]; then
  echo "installing pip"
  sudo apt-get install python-pip
fi
echo "installing pip packages"
sudo pip install pymongo pyelftools blist 

# we need realpath...err ok for now
if [ ! $(which realpath) ]; then
  echo "installing realpath"
  sudo apt-get install realpath
fi

# we need meteor
if [ ! -d ~/.meteor ]; then
  echo "installing meteor"
  curl https://install.meteor.com | /bin/sh
fi

# and mrt
if [ ! -f ~/.meteor/tools/latest/bin/mrt ]; then
  ~/.meteor/tools/latest/bin/npm install -g meteorite
fi

echo "making symlinks"
sudo ln -sf $(pwd)/qira /usr/local/bin/qira
sudo ln -sf $(pwd)/qira-server /usr/local/bin/qira-server
sudo ln -sf $(pwd)/qemu/qira-i386 /usr/local/bin/qira-i386
sudo ln -sf $(pwd)/qemu/qira-arm /usr/local/bin/qira-arm
sudo ln -sf $(pwd)/qemu/qira-sparc /usr/local/bin/qira-sparc
sudo ln -sf $(pwd)/qemu/qira-sparc32plus /usr/local/bin/qira-sparc32plus
sudo ln -sf $(pwd)/qemu/qira-x86_64 /usr/local/bin/qira-x86_64

