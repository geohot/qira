#!/bin/bash -e

# test distribution
if [ "$1" == "distrib" ] ; then
  echo "*** testing distrib"
  ./bdistrib.sh
  cd distrib/qira
  ./install.sh
  cd ../../
fi

bap-server &

source venv/bin/activate
nosetests

# integration test
qira qira_tests/bin/loop &
QIRA_PID=$!
echo "qira pid is $QIRA_PID"
sleep 2

# phantomjs
phantomjs qira_tests/load_page.js

killall bap-server
kill $QIRA_PID
