#!/bin/sh
set -e
g++ qiradb.cc -lmongoc-1.0 -lbson-1.0 -o qiradb

