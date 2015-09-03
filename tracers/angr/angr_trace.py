import sys
import angr
import os

# import from the qira middleware directory
basedir = os.path.dirname(os.path.realpath(__file__)) + "/../../middleware"
sys.path.append(basedir)
import qira_log

# run the program in angr, isn't realtime yet
p = angr.Project(sys.argv[1])
pg = p.factory.path_group(immutable=False)
pg.step(until=lambda lpg: len(lpg.deadended) > 1)

# extract the trace and the concretize function
pgd = pg.deadended[0]
conc = pgd.state.se.any_int

# loop and extract the log
log = []
clnum = 0
for x in pgd.actions:
  print x

  # wtf?
  try:
    if x.addr is None:
      continue
  except:
    continue

  # filter types
  if x.type != "mem" and x.type != "reg":
    continue

  address = x.addr.ast
  if type(address) != int:
    # BV has .size() also
    address = conc(address)
  
  if x.type == "reg":
    rn = p.arch.register_names[address]
    if rn == "eip" and x.action == "write":
      print rn, "INSTRUCTION",hex(data)
      # new instruction
      log.append((data, 0, clnum, qira_log.IS_VALID | qira_log.IS_START))
      clnum += 1

  # this is wrong
  data = conc(x.data) & 0xFFFFFFFFFFFFFFFF

  flags = qira_log.IS_VALID
  if x.type == "mem":
    flags |= qira_log.IS_MEM
  if x.action == "write":
    flags |= qira_log.IS_WRITE

  le = (address, data, clnum, flags)
  print le

  log.append(le)

# write the qira log
qira_log.write_log(qira_log.LOGDIR + "0", log)


#pg.step(until=lambda lpg: len(lpg.active) > 1)
"""
pg.active
pg.step()
pg.active
pg.step()
pg.active
pg.active[0].backtrace
p._sim_procedures
[ hex(x) for x in p._sim_procedures.keys() ]
pg.step()
pg.active
pg.step()
pg.active
"""

#pg.step(200)

#[ path.state.posix.dumps(1) for path in pg.deadended ]
#[ path.state.posix.dumps(0) for path in pg.deadended ]
#[ hex(x) for x in p._sim_procedures.keys() ]
#[ (hex(x[0]), x[1]) for x in p._sim_procedures.items() ]
#pg.deadended[0]



"""
pg.deadended[0].actions[0]
pg.deadended[0].actions[0].type
pg.deadended[0].actions[0].addr
pg.deadended[0].actions[0].addr.ast
p.arch.register_names[pg.deadended[0].actions[0].addr.ast]
pg.deadended[0].state.se.any_int(pg.deadended[0].actions[0].data)
pg.deadended[0].state.se.any_int(pg.deadended[0].actions[0].data)
pg.deadended[0].actions[0].action
"""

# pg.deadended[0].state.se.any_int

