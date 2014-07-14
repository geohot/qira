#!/bin/sh
rm -f *.js
FILES=$(grep packages ../index.html | awk '{ print $3 }' | sed 's/src="/http:\/\/localhost:3000/' | sed 's/?.*//')
echo $FILES
wget $FILES

