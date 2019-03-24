#!/bin/bash -e

source venv/bin/activate

# ned's tests, which are really awesome
# why weren't these used?
cd tests_auto
#./autogen-extras.sh
#python autogen.py --dwarf --all
python autogen.py --dwarf
cd ../
cd static2
python3 testing.py
