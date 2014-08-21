#!/bin/sh
set -e
g++ qiradb.cc -O3 -lmongoc-1.0 -lbson-1.0 -o qiradb

