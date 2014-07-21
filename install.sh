#!/bin/bash
set -e

# for building blist and stuff for flask like gevent

# we need pip to install python stuff
if [ $(which apt-get) ]; then
  echo "installing apt packages"
  sudo apt-get install build-essential python-dev python-pip
fi

echo "installing pip packages"
sudo pip install blist flask-socketio

echo "making symlinks"
sudo ln -sf $(pwd)/qira /usr/local/bin/qira

