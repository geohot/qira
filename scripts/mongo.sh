#!/bin/bash
set -e
numactl --interleave=all ~/build/mongodb-linux-x86_64-2.6.3/bin/mongod --dbpath=$(pwd)/db --bind_ip 127.0.0.1

