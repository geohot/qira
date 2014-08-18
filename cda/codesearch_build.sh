#!/bin/bash -e
wget -O /tmp/cs.zip https://codesearch.googlecode.com/files/codesearch-0.01-linux-amd64.zip
unzip -o /tmp/cs.zip
rm /tmp/cs.zip
ln -sf codesearch-0.01 codesearch-latest

