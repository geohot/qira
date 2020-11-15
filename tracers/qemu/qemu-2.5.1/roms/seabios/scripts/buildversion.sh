#!/bin/sh
# Script to generate a C file with version information.
OUTFILE="$1"
VAR16MODE="$2"

# Extract version info
if [ -z "$BUILD_VERSION" ]; then
    if [ -d .git -o -f .git ]; then
        VERSION="`git describe --tags --long --dirty`"
    elif [ -f .version ]; then
        VERSION="`cat .version`"
    else
        VERSION="?"
    fi
    VERSION="${VERSION}-`date +"%Y%m%d_%H%M%S"`-`hostname`"
else
    VERSION="$BUILD_VERSION"
fi
echo "Version: ${VERSION}"

# Build header file
if [ "$VAR16MODE" = "VAR16" ]; then
    cat > ${OUTFILE} <<EOF
#include "types.h"
char VERSION[] VAR16 = "${VERSION}";
EOF
else
    cat > ${OUTFILE} <<EOF
char VERSION[] = "${VERSION}";
EOF
fi
