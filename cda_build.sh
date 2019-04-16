#!/bin/bash -e

echo "installing cda packages"
sudo apt-get install libclang-3.4-dev

echo "installing codesearch"
pushd .
cd cda
wget -O /tmp/cs.zip https://codesearch.googlecode.com/files/codesearch-0.01-linux-amd64.zip
unzip -o /tmp/cs.zip
rm /tmp/cs.zip
ln -sf codesearch-0.01 codesearch-latest
popd

echo "making symlink"
sudo ln -sf $(pwd)/qira /usr/local/bin/cda
