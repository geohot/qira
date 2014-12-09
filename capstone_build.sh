#!/bin/bash -e
mkdir -p capstone
cd capstone
if [ ! -d capstone-3.0 ]; then
  echo "downloading capstone"
  wget http://www.capstone-engine.org/download/3.0/capstone-3.0.tgz
  tar xf capstone-3.0.tgz
fi

cd capstone-3.0
./make.sh
sudo ./make.sh install

