import qiradb
import time
#print dir(qiradb)

LIMIT = 10000

#print "new_trace:", qiradb.new_trace("/tmp/qira_logs/0", 0, 4, 16)
#time.sleep(100000.0)

# register size = 4, register count = 9
def test():
  t = qiradb.Trace("qira_tests/bin/hello_trace", 0, 4, 9, False)
  print "trace created"

  while not t.did_update():
    print "waiting..."
    time.sleep(0.1)

  # get max change
  ret = t.get_maxclnum()
  print "maxclnum:",ret
  assert ret == 116

  # get min change
  ret = t.get_minclnum()
  print "minclnum:",ret
  assert ret == 0

  # who loads argc?
  ret = t.fetch_clnums_by_address_and_type(0xf6fff090, 'L', 0, 1000, LIMIT)
  print "load argc:",ret
  assert ret == [0,2]

  # fetch registers
  ret = t.fetch_registers(113)
  print "fetch regs:",map(hex, ret)
  assert len(ret) == 9
  assert ret[8] == 0x80484d1
  assert ret[4] == 0xf6ffef00

  # fetch memory
  ret = t.fetch_memory(0, 0xf6fff080, 0x10)
  print ret
  ret = t.fetch_memory(7, 0xf6fff080, 0x10)
  print ret
  ret = t.fetch_memory(116, 0xf6fff080, 0x10)
  print ret

  # was a pop %esi
  ret = t.fetch_changes_by_clnum(2, LIMIT)
  print "pop esi:",ret

  print t.get_pmaps()

  """
  while 1:
    ret = t.fetch_clnums_by_address_and_type(0xf6fff090, 'L', 0, LIMIT)
    ret = t.fetch_registers(113)
    ret = t.fetch_memory(0, 0xf6fff080, 0x10)
  """

