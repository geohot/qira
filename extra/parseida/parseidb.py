import sys
from hexdump import hexdump

# name.id0 - contains contents of B-tree style database
# name.id1 - contains flags that describe each program byte
# name.nam - contains index information related to named program locations
# name.til - contains information about local type definitions

BTREE_PAGE_SIZE = 8192

#dat = open(sys.argv[1]).read()

#id0 = dat[0x104:]

dat = open("/Users/geohot/tmp/test.id0").read()
print hex(len(dat)), len(dat)/BTREE_PAGE_SIZE

for i in range(0, len(dat), BTREE_PAGE_SIZE):
  hexdump(dat[i:i+0xC0])
  print ""




