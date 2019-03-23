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
trap "kill $QIRA_PID" EXIT
echo "qira pid is $QIRA_PID"
sleep 2

# replace phantomjs test with this
#phantomjs qira_tests/load_page.js
curl http://localhost:3002/ | grep "<title>qira</title>kk"

echo "tests pass"

