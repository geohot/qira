#!/bin/sh
rm -f *.js
wget http://localhost:3000/template.qira.js
#wget $(grep style index.html | awk '{ print $3 }' | sed 's/href="/http:\/\/localhost:3000/' | sed 's/\.css.*/\.map/')
#wget $(grep style index.html | awk '{ print $3 }' | sed 's/href="/http:\/\/localhost:3000/' | sed 's/\.css.*/\.css/')

JSFILES=$(wget -qO- http://localhost:3000/index.html | grep packages | awk '{ print $3 }' | sed 's/src="/http:\/\/localhost:3000/' | sed 's/?.*//' | grep -v "livedata" | grep -v "autoupdate" | grep -v "application-configuration")
echo $JSFILES
wget -qO- $JSFILES | grep -v "^//# sourceMappingURL=" | grep -v "DDP = Package.livedata.DDP;$" | grep -v "Autoupdate = Package.autoupdate.Autoupdate;$" > package.js
yui-compressor package.js -o package.js

# *** FOR DEBUGGING ***

#JSFILES=$(wget -qO- http://localhost:3000/index.html | grep packages | awk '{ print $3 }' | sed 's/src="/http:\/\/localhost:3000/' | sed 's/?.*//')
#cd packages
#wget -q $JSFILES

