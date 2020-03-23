#!/bin/bash
set -xe
cd "$(dirname "$0")/pin"

case "`uname`" in
Linux)
  if test -d pin-latest; then true; else
    curl -L https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz | tar xz
    ln -s pin-3.7-97619-g0d0c92f4f-gcc-linux pin-latest
  fi

  # pin build deps, good?
  if which apt-get; then
    echo "apt-getting pin tool building deps"
    sudo apt-get -qq -y install g++-7 gcc-7-multilib g++-7-multilib || echo "WARNING: apt-get failed"
  else
    echo "WARNING: you don't have apt-get, you are required to fetch pin tool building deps (e.g. 32 bit libs) on your own"
  fi

  PIN_ROOT=./pin-latest TARGET=intel64 make CXX=g++-7
  PIN_ROOT=./pin-latest TARGET=ia32 make CXX=g++-7
  ;;

Darwin)
  if test -d pin-latest; then true; else
    curl -L https://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-71313-clang.5.1-mac.tar.gz | tar xz
    ln -s pin-2.14-71313-clang.5.1-mac pin-latest
  fi

  PIN_ROOT=./pin-latest TARGET=intel64 make
  PIN_ROOT=./pin-latest TARGET=ia32 make
  ;;

CYGWIN*)
  REQUTILS="curl unzip rm ln bash realpath make"
  which $REQUTILS > /dev/null || { echo You must first use Cygwin to install $REQUTILS; exit 1; }
  if test -d pin-latest; then true; else
    curl -LO https://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-71313-msvc12-windows.zip
    unzip -q pin-2.14-71313-msvc12-windows.zip
    rm pin-2.14-71313-msvc12-windows.zip
    ln -s pin-2.14-71313-msvc12-windows pin-latest
  fi

  rm -f ./vs_community_2013.exe
  if test -d 'C:\Program Files (x86)\Microsoft Visual Studio 12.0'; then
    export VC='C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC'
    export PIN_ROOT="$(cygpath -w "$(realpath ./pin-latest)")"
    ( { echo '"%VC%\bin\vcvars32.bat"'; echo 'make TARGET=ia32'; } | cmd )
    ( { echo '"%VC%\bin\amd64\vcvars64.bat"'; echo 'make TARGET=intel64'; } | cmd )
  else
    echo "You need vc12 to compile this PIN (newer versions probably won't work)."
    curl -L 'http://go.microsoft.com/fwlink/?LinkId=517284' > vs_community_2013.exe
    echo "Use the GUI to install Visual Studio and reboot. Run $0 again afterwards."
    if test -z "$SSH_CLIENT"; then
      ./vs_community_2013.exe
    else
      echo "Invoke ./vs_community_2013.exe from the GUI (sshd usually can't launch gui apps)."
    fi
    exit 0
  fi
  ;;
esac
