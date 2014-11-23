#!/bin/bash -e
source venv/bin/activate
nosetests

# integration test
qira qira_tests/bin/loop &
QIRA_PID=$!
echo "qira pid is $QIRA_PID"
sleep 2

# phantomjs
phantomjs qira_tests/load_page.js

kill $QIRA_PID


