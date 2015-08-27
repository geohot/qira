#!/bin/bash -e

source venv/bin/activate

# ned's tests, which are really awesome
# why weren't these used?
cd tests_auto
python autogen.py --dwarf --all
cd ../
cd static2
python testing.py

