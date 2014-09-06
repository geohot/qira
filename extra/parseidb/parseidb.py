import sys
from hexdump import hexdump

BTREE_PAGE_SIZE = 8192

#dat = open(sys.argv[1]).read()

#id0 = dat[0x104:]

dat = open("/Users/geohot/tmp/test.id0").read()
print hex(len(dat)), len(dat)/BTREE_PAGE_SIZE

for i in range(0, len(dat), BTREE_PAGE_SIZE):
  hexdump(dat[i:i+0x20])
  print ""




