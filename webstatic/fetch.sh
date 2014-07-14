#!/bin/sh
rm -f *.html *.js *.css *.map
wget http://localhost:3000/index.html http://localhost:3000/template.qira.js
#wget $(grep style index.html | awk '{ print $3 }' | sed 's/href="/http:\/\/localhost:3000/' | sed 's/\.css.*/\.map/')
#wget $(grep style index.html | awk '{ print $3 }' | sed 's/href="/http:\/\/localhost:3000/' | sed 's/\.css.*/\.css/')

cd packages

rm -f *.js
JSFILES=$(grep packages ../index.html | awk '{ print $3 }' | sed 's/src="/http:\/\/localhost:3000/' | sed 's/?.*//')
echo $JSFILES
wget -q $JSFILES

rm -f *.map
MAPFILES=$(grep packages ../index.html | awk '{ print $3 }' | sed 's/[^?]*?/http:\/\/localhost:3000\/packages\//' | sed 's/".*/\.map/')
echo $MAPFILES
wget -q $MAPFILES

CSSFILE=$(grep style ../index.html | awk '{ print $3 }' | sed 's/[^?]*?/http:\/\/localhost:3000\/packages\//' | sed 's/".*/\.map/')

