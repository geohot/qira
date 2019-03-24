#!/bin/bash

# simple loop test
docker run --workdir /qira --rm qira bash -c "./run_tests.sh && ./run_tests_static.sh"
#docker run -p 3002:3002 --rm qira qira qira_tests/bin/loop

