#!/bin/bash -e

# default is just pip, but on things like arch where python 3 is default, it's pip2
if [ $(which pip2) ]; then
    PIP="pip2"
else
    PIP="pip"
fi

LIBCAPSTONE64_SHA256="a7bf1cb814c6e712a314659b074bc4c00d2e0006cac67d055d3130d4ecdd525d"
LIBCAPSTONE32_SHA256="4ffb4630829b9b4e8c713ae8336a8259b180194233f248170bfe0d1577257fb2"

unamestr=$(uname)
arch=$(uname -p)

if [[ "$unamestr" == 'Linux' ]]; then
  # we need pip to install python stuff
  # build for building qiradb and stuff for flask like gevent
  if [ $(which apt-get) ]; then
    echo "running apt-get update"
    sudo apt-get update -qq
    echo "installing apt packages"
    sudo apt-get -qq -y install build-essential debootstrap debian-archive-keyring libjpeg-dev zlib1g-dev unzip wget graphviz curl
    echo "install python packages"
    sudo apt-get -qq -y install python-dev python-pip python-virtualenv

    # install capstone
    if [ "$arch" == 'i686' ]; then
        curl -o /tmp/libcapstone3.deb http://www.capstone-engine.org/download/3.0.4/ubuntu-14.04/libcapstone3_3.0.4-0.1ubuntu1_i386.deb
    else
        curl -o /tmp/libcapstone3.deb http://www.capstone-engine.org/download/3.0.4/ubuntu-14.04/libcapstone3_3.0.4-0.1ubuntu1_amd64.deb
    fi
    
    HASH=`sha256sum /tmp/libcapstone3.deb 2>/dev/null | cut -d' ' -f1`
    if [ "$HASH" != "$LIBCAPSTONE64_SHA256" ] && [ "$HASH" != "$LIBCAPSTONE32_SHA256" ]; then
      echo "Error: libcapstone3.deb has an invalid checksum."
      exit 1
    fi
    sudo dpkg -i /tmp/libcapstone3.deb

  elif [ $(which pacman) ]; then
    echo "installing pip"
    sudo pacman -S --needed --noconfirm base-devel python2-pip python2-virtualenv
    PIP="pip2"
  elif [ $(which dnf) ]; then
    sudo dnf install -y python-pip python-devel gcc gcc-c++ python-virtualenv glib2-devel
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
  if [ $(which brew) ]; then
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

