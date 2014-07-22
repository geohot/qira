import qiradb
import time
#print dir(qiradb)

LIMIT = 10000

#print "new_trace:", qiradb.new_trace("/tmp/qira_logs/0", 0, 4, 16)
#time.sleep(100000.0)

# register size = 4, register count = 9
print "new_trace:", qiradb.new_trace(0, "hello_trace", 4, 9)

while not qiradb.did_update(0):
  print "waiting..."
  time.sleep(0.1)

# get max change
ret = qiradb.get_maxclnum(0)
print "maxclnum:",ret
assert ret == 116

# who loads argc?
ret = qiradb.fetch_clnums_by_address_and_type(0, 0xf6fff090, 'L', 0, LIMIT)
print "load argc:",ret
assert ret == [0,2]

# fetch registers
ret = qiradb.fetch_registers(0, 113)
print "fetch regs:",map(hex, ret)
assert len(ret) == 9
assert ret[8] == 0x80484d1
assert ret[4] == 0xf6ffef00

# fetch memory
ret = qiradb.fetch_memory(0, 0, 0xf6fff080, 0x10)
print ret
ret = qiradb.fetch_memory(0, 7, 0xf6fff080, 0x10)
print ret
ret = qiradb.fetch_memory(0, 116, 0xf6fff080, 0x10)
print ret

# was a pop %esi
ret = qiradb.fetch_changes_by_clnum(0, 2, LIMIT)
print "pop esi:",ret



