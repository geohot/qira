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

# phantomjs
# use phantomjs2.0 for non-draft WebSockets protol
# unforunately this doesn't ship with Ubuntu by default
# the next 3 lines are 12.04 specific. maybe we should update Travis at some point
sudo apt-get install libicu48
wget https://s3.amazonaws.com/travis-phantomjs/phantomjs-2.0.0-ubuntu-12.04.tar.bz2
tar xf ./phantomjs-2.0.0-ubuntu-12.04.tar.bz2
chmod +x ./phantomjs
./phantomjs qira_tests/load_page.js

kill $QIRA_PID

