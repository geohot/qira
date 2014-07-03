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

# we need meteor
if [ ! -d ~/.meteor ]; then
  echo "installing meteor"
  curl https://install.meteor.com | /bin/sh
fi

if [ ! -f /usr/local/bin/qira ]; then
  echo "making symlinks"
  sudo ln -s $(pwd)/qira /usr/local/bin/qira
  sudo ln -s $(pwd)/qira-server /usr/local/bin/qira-server
  sudo ln -s $(pwd)/qemu/qira-i386 /usr/local/bin/qira-i386
fi

