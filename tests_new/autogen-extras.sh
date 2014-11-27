#!/bin/bash -e
#installs support for cross-compiled architectures on Ubuntu 14.04

sudo apt-get -y install clang gcc-4.8-multilib gcc-4.8-aarch64-linux-gnu gcc-4.8-arm-linux-gnu gcc-4.8-powerpc-linux-gnu gcc-4.8-powerpc64le-linux-gnu
