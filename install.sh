#!/bin/bash
set -e

# default is just pip, but on things like arch where python 3 is default, it's pip2
PIP="pip"

# we need pip to install python stuff
# build for building qiradb and stuff for flask like gevent
if [ $(which apt-get) ]; then
  echo "installing apt packages"
  sudo apt-get install build-essential python-dev python-pip debootstrap
elif [ $(which pacman) ]; then
  echo "installing pip"
  sudo pacman -S base-devel python2-pip
  PIP="pip2"
fi

echo "installing pip packages"
sudo $PIP install flask-socketio pillow ./qiradb

echo "making symlinks"
sudo ln -sf $(pwd)/qira /usr/local/bin/qira

