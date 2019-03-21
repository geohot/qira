#!/bin/bash -e

# test distribution
if [ "$1" == "distrib" ] ; then
  echo "*** testing distrib"
  ./bdistrib.sh
  cd distrib/qira
  ./install.sh
  cd ../../
fi

source venv/bin/activate
nosetests

# integration test
qira qira_tests/bin/loop &
QIRA_PID=$!
echo "qira pid is $QIRA_PID"
sleep 2

LSB="/etc/lsb-release"
VER="12.04"
LIBICU="libicu48"

if [ -f $LSB ] ; then
  echo "*** Debian Based Distro."
  . $LSB
  if [ $DISTRIB_ID == "Ubuntu" ]; then
    if [ $DISTRIB_RELEASE != "12.04" ]; then
      VER="14.04"
      LIBICU="libicu52"
    fi
  fi
fi

# phantomjs
# use phantomjs2.0 for non-draft WebSockets protol
# unforunately this doesn't ship with Ubuntu by default
if [ $(sudo apt-get install $LIBICU; echo $?) != 100 ]; then
    echo "libcsu55 installed successfully."
else
    echo "missing dependencies, fixing source"
    echo -e "deb http://security.ubuntu.com/ubuntu trusty-security main" | sudo tee -a /etc/apt/sources.list
    sudo apt-get update
    sudo apt-get install $LIBICU
fi

wget https://s3.amazonaws.com/travis-phantomjs/phantomjs-2.0.0-ubuntu-$VER.tar.bz2
tar xf ./phantomjs-2.0.0-ubuntu-$VER.tar.bz2
chmod +x ./phantomjs
./phantomjs qira_tests/load_page.js

kill $QIRA_PID

