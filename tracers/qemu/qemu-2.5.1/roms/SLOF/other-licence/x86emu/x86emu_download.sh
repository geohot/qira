# *****************************************************************************
# * Copyright (c) 2004, 2008 IBM Corporation
# * All rights reserved.
# * This program and the accompanying materials
# * are made available under the terms of the BSD License
# * which accompanies this distribution, and is available at
# * http://www.opensource.org/licenses/bsd-license.php
# *
# * Contributors:
# *     IBM Corporation - initial implementation
# ****************************************************************************/
#!/bin/bash

#set -x
#set -e

SVN=`which svn`
PATCH=`which patch`
DIFF_FILE=./x86emu_changes.diff

# check wether svn, patch, ... is available...

if [ ! -x $SVN ]; then
	echo "subversion executable not found!"
	exit -1
fi
if [ ! -x $PATCH ]; then
	echo "patch executable not found!"
	exit -1
fi
if [ ! -r $DIFF_FILE ]; then
	echo "diff file $DIFF_FILE not found!"
	exit -1
fi

# download the x86emu sources from LinuxBIOS subversion

#revision known to work...
REV=496

echo "Checking out x86emu from coreboot-v3 repository revision $REV"
$SVN co svn://coreboot.org/repository/coreboot-v3/util/x86emu -r $REV

echo "Copying files..."

mkdir -p include/x86emu
cp -v x86emu/x86emu/*.c .
cp -v x86emu/x86emu/*.h include/x86emu
cp -v x86emu/include/x86emu/*.h include/x86emu

echo "Removing checkedout subversion director..."

rm -rf x86emu

echo "Patching files..."

$PATCH -p0 < x86emu_changes.diff


echo "done"
exit 0
