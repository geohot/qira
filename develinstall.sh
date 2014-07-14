#!/bin/bash
set -e

./install.sh
./qemu_build.sh

# we need meteor
if [ ! -d ~/.meteor ]; then
  echo "installing meteor"
  curl https://install.meteor.com | /bin/sh
fi

# and mrt
if [ ! -f ~/.meteor/tools/latest/bin/mrt ]; then
  ~/.meteor/tools/latest/bin/npm install -g meteorite
fi

echo "making devel symlinks"
sudo ln -sf $(pwd)/qemu/qira-sparc /usr/local/bin/qira-sparc
sudo ln -sf $(pwd)/qemu/qira-sparc32plus /usr/local/bin/qira-sparc32plus
sudo ln -sf $(pwd)/qemu/qira-x86_64 /usr/local/bin/qira-x86_64

