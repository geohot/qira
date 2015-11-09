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
sudo apt-get install libicu52
wget https://github.com/nedwill/phantomjs2.0-ubuntu14.04x64/raw/master/bin/phantomjs
chmod +x ./phantomjs
./phantomjs qira_tests/load_page.js

kill $QIRA_PID

