#!/bin/bash -e

# default is just pip, but on things like arch where python 3 is default, it's pip2
if [ $(which pip2) ]; then
    PIP="pip2"
else
    PIP="pip"
fi

LIBCAPSTONE_SHA256="a7bf1cb814c6e712a314659b074bc4c00d2e0006cac67d055d3130d4ecdd525d"

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
    HASH=`sha256sum /tmp/libcapstone3.deb 2>/dev/null | cut -d' ' -f1`

    if [ "$HASH" != "$LIBCAPSTONE_SHA256" ]; then

      echo "Error: libcapstone3.deb has an invalid checksum."
      exit 1

    fi

    sudo dpkg -i /tmp/libcapstone3.deb

    # only python package we install globally
    sudo -H $PIP install virtualenv
  elif [ $(which pacman) ]; then
    echo "installing pip"
    sudo pacman -S --needed --noconfirm base-devel python2-pip python2-virtualenv
    PIP="pip2"
  elif [ $(which yum) ]; then
    sudo yum install -y python-pip python-devel gcc gcc-c++ python-virtualenv glib2-devel
  fi

  if [ $(tracers/qemu/qira-i386 > /dev/null; echo $?) == 1 ]; then
    echo "QIRA QEMU appears to run okay"
  else
    echo "building QEMU"
    cd tracers
    ./qemu_build.sh
    cd ../
  fi
elif [[ "$unamestr" == 'Darwin' ]]; then
  if [ $(brew > /dev/null; echo $?) == 1 ]; then
    echo "Installing OS X dependencies"
    brew update
    brew install python capstone
    pip install virtualenv
    cd tracers
    ./pin_build.sh
    cd ../
  else
    echo "build script only supports Homebrew"
  fi
fi

echo "installing pip packages"

if [ $(which virtualenv2) ]; then
    VIRTUALENV="virtualenv2"
else
    VIRTUALENV="virtualenv"
fi

$VIRTUALENV venv
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

