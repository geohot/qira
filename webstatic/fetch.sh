#!/bin/sh
rm -f *.html *.js
wget http://localhost:3000/index.html http://localhost:3000/template.qira.js

cd packages

rm -f *.js
JSFILES=$(grep packages ../index.html | awk '{ print $3 }' | sed 's/src="/http:\/\/localhost:3000/' | sed 's/?.*//')
echo $JSFILES
wget $JSFILES

rm -f *.map
MAPFILES=$(grep packages ../index.html | awk '{ print $3 }' | sed 's/[^?]*?/http:\/\/localhost:3000\/packages\//' | sed 's/".*/\.map/')
echo $MAPFILES
wget $MAPFILES

