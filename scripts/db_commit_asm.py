from pymongo import MongoClient
db = MongoClient('localhost', 3001).meteor

ds = []

dat = open("/tmp/qira_disasm").read().split("\n")
for d in dat:
  if ":  " in d:
    (addr, inst) = d.split(":  ")
    addr = int(addr, 16)
    #print addr, inst
    d = {'address': addr, 'instruction': inst}
    ds.append(d)

# DWARF data will go here too
coll = db.program
print "doing db insert"
coll.drop()
coll.insert(ds)
print "db insert done, building indexes"
coll.ensure_index("address")
print "indexes built"


