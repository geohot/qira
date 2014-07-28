#!/bin/bash -e

./install.sh
./qemu_build.sh

# we need meteor
if [ ! -d ~/.meteor ]; then
  echo "installing meteor"
  sudo apt-get install curl
  curl https://install.meteor.com | /bin/sh
fi

# and mrt
if [ ! -f ~/.meteor/tools/latest/bin/mrt ]; then
  ~/.meteor/tools/latest/bin/npm install -g meteorite
fi


