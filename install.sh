#!/bin/bash
set -e

# we need pymongo
if ! python -c 'import pymongo; exit(0)'; then
  if [ ! $(which pip) ]; then
    echo "installing pip"
    sudo apt-get install python-pip
  fi
  echo "installing pymongo"
  sudo pip install pymongo
fi

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

