#!/usr/bin/env bash
set -euo pipefail

if [[ ! -d venv ]]; then
  python3 -m venv venv
fi

source venv/bin/activate
python -m pip install --upgrade pip setuptools wheel

# install system deps (Linux)
if command -v apt-get >/dev/null 2>&1; then
  echo "installing deps for ubuntu"
  sudo apt-get update
  sudo apt-get -y install git curl python3 python3-venv python3-dev python3-pip build-essential pkg-config zlib1g-dev libglib2.0-dev libpixman-1-dev
elif [[ "$(uname)" == "Darwin" ]]; then
  echo "installing deps for macOS"
  if command -v brew >/dev/null 2>&1; then
    brew install python pkg-config glib pixman
  else
    echo "*** Homebrew not found. Install Homebrew, then rerun install.sh ***"
    exit 1
  fi
else
  echo "*** Please install python3, venv support, and build tooling for your platform manually ***"
fi

# build qemu
if [[ "$(uname)" == 'Linux' ]]; then
  if tracers/qemu/qira-i386 >/dev/null 2>&1; then
    echo "QIRA QEMU appears to run okay"
  else
    echo "building QEMU"
    cd tracers
    ./qemu_build.sh
    cd ../
  fi
else
  echo "QEMU user only works on Linux."
  echo "While the rest of QIRA will run, you cannot run binaries."
  echo "This is due to QEMU user forwarding the syscalls to the kernel."
  echo "See other backends in qira/tracers, PIN may work on Windows and OS X"
fi

echo "installing Python dependencies"
python -m pip install --upgrade -r requirements.txt

echo "running tests"
./run_tests.sh

echo "making systemwide symlink"
sudo ln -sf $(pwd)/qira /usr/local/bin/qira

echo "***************************************"
echo "  Thanks for installing QIRA"
echo "  Check out README for more info"
echo "  Or just dive in with 'qira /bin/ls'"
echo "  And point Chrome to localhost:3002"
echo "    ~geohot"
