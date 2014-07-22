#!/bin/sh -e
sudo rm -rf build
sudo python setup.py install
cd test
python test.py

