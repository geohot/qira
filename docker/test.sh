#!/bin/bash

# simple loop test
docker run --workdir /qira --rm qira ./run_tests.sh
#docker run -p 3002:3002 --rm qira qira qira_tests/bin/loop

