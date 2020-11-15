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
#!/bin/sh


CROSSTMP=`grep ^CROSS $(dirname $0)/../make.rules | cut -d\  -f2`

CROSS=${CROSS-$CROSSTMP}

# Set defaults:
LD="${CROSS}ld"
LDFLAGS="-nostdlib"
LDSFILE=""
OBJCOPY="${CROSS}objcopy"

DIRNAME=`dirname $0`

# Parse parameters:
while [ $# -gt 0 ] ; do
	case "$1" in
		--ld) LD=$2 ; shift 2 ;;
		--ldflags) LDFLAGS=$2 ; shift 2 ;;
		--lds) LDSFILE=$2 ; shift 2 ;;
		--objcopy) OBJCOPY=$2 ; shift 2 ;;
		*.o|*.a|-l*|-L*) OBJFILES="$OBJFILES $1" ; shift ;;
		*) echo "$0:" ; echo " Unsupported argument: $1"; exit -1 ;;
	esac
done

if [ -z $LDSFILE ]; then
	echo "Please specifiy an lds file with the --lds option"
	exit 42
fi

TMP1=`mktemp`
TMP2=`mktemp`

# Now create the two object files:
$LD $LDFLAGS -T $LDSFILE -o $TMP1.o $OBJFILES || exit -1
$LD $LDFLAGS -T $LDSFILE -o $TMP2.o $OBJFILES --section-start .text=0x4000000000000000 || exit -1

$OBJCOPY -O binary $TMP1.o $TMP1.bin || exit -1
$OBJCOPY -O binary $TMP2.o $TMP2.bin || exit -1

# Create the relocation table with gen_reloc_table:
$DIRNAME/gen_reloc_table $TMP1.bin $TMP2.bin reloc_table.bin

$LD -o reloc_table.o -bbinary reloc_table.bin -e0 || exit -1
$OBJCOPY --rename-section .data=.reloc reloc_table.o reloc_table.o || exit -1

rm -f $TMP1.o $TMP2.o $TMP1.bin $TMP2.bin reloc_table.bin
