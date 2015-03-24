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
    sudo apt-get -qq -y install build-essential python-dev python-pip debootstrap libjpeg-dev zlib1g-dev unzip wget graphviz

    # only python package we install globally
    sudo -H $PIP install virtualenv

    echo "fetching BAP deps"
    sudo apt-get install -qq -y software-properties-common libgmp-dev llvm-3.4-dev time clang-3.4

    echo "installing ocaml and opam"
    echo 'yes' | sudo add-apt-repository ppa:avsm/ocaml42+opam12
    sudo apt-get update -qq
    sudo apt-get install -qq -y ocaml ocaml-native-compilers camlp4-extra opam
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

echo "preparing opam"
export OPAMYES=1
export OPAMJOBS=$(grep processor < /proc/cpuinfo | wc -l)
opam init
opam update

echo "installing BAP"
#export OPAMVERBOSE=1
# needed so travis doesn't give up on us after 10 minutes of no output
python -mtimeit "import time; start=time.time()" \
  "while 1: time.sleep(30); print 'still building BAP: %5.2fm elapsed' % ((time.time()-start)/60)" &
llvm_version=3.4 opam install bap
kill %%

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

