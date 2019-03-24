#!/bin/bash
./build.sh qira
docker run -i --rm qira:latest bash -c "./run_tests.sh && ./run_tests_static.sh"
