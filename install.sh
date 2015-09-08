#!/bin/bash -e

# default is just pip, but on things like arch where python 3 is default, it's pip2
PIP="pip"

unamestr=$(uname)
if [[ "$unamestr" == 'Linux' ]]; then
  # we need pip to install python stuff
  # build for building qiradb and stuff for flask like gevent
  if [ $(which apt-get) ]; then
    echo "installing apt packages"
    sudo apt-get update -qq
    sudo apt-get -qq -y install build-essential python-dev python-pip debootstrap debian-archive-keyring libjpeg-dev zlib1g-dev unzip wget graphviz curl

    # install capstone
    curl -o /tmp/libcapstone3.deb http://www.capstone-engine.org/download/3.0.4/ubuntu-14.04/libcapstone3_3.0.4-0.1ubuntu1_amd64.deb
    sudo dpkg -i /tmp/libcapstone3.deb

    # only python package we install globally
    sudo -H $PIP install virtualenv
  elif [ $(which pacman) ]; then
    echo "installing pip"
    sudo pacman -S base-devel python2-pip
    PIP="pip2"
  elif [ $(which yum) ]; then
    sudo yum install python-pip python-devel gcc gcc-c++ python-virtualenv glib2-devel
  fi

  if [ $(tracers/qemu/qira-i386 > /dev/null; echo $?) == 1 ]; then
    echo "QIRA QEMU appears to run okay"
  else
    echo "building QEMU"
    cd tracers
    ./qemu_build.sh
    cd ../
  fi
fi

echo "installing pip packages"
virtualenv venv
source venv/bin/activate
$PIP install --upgrade -r requirements.txt

echo "making symlink"
sudo ln -sf $(pwd)/qira /usr/local/bin/qira

echo "***************************************"
echo "  Thanks for installing QIRA"
echo "  Check out README for more info"
echo "  Or just dive in with 'qira /bin/ls'"
echo "  And point Chrome to localhost:3002"
echo "    ~geohot"

