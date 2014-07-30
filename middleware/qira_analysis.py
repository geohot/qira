import qira_config
import qira_program
import time

def ghex(a):
  if a == None:
    return None
  return hex(a).strip("L")

def draw_multigraph(blocks):
  import pydot

  print "generating traces"

  arr = []
  trace = []
  cls = []
  for i in range(len(blocks)):
    h = ghex(blocks[i]['start']) + "-" + ghex(blocks[i]['end'])
    if h not in arr:
      arr.append(h)
    trace.append(arr.index(h))
    cls.append(blocks[i]['clstart'])


  # this is the whole graph with an edge between each pair
  #print trace
  #print cls

  graph = pydot.Dot(graph_type='digraph')

  print "adding nodes"
  nodes = []
  for a in arr:
    n = pydot.Node(a, shape="box")
    graph.add_node(n)
    nodes.append(n)

  edges = []
  cnts = []

  print "trace size",len(trace)
  print "realblock count",len(arr)

  print "counting edges"
  for i in range(0, len(trace)-1):
    #e = pydot.Edge(nodes[trace[i]], nodes[trace[i+1]], label=str(cls[i+1]), headport="n", tailport="s")
    te = [nodes[trace[i]], nodes[trace[i+1]]]
    if te not in edges:
      edges.append(te)
      cnts.append(1)
    else:
      a = edges.index(te)
      cnts[a] += 1

  print "edge count",len(edges)

  print "adding edges"
  for i in range(len(edges)):
    te = edges[i]
    #print cnts[i]
    if cnts[i] > 1:
      e = pydot.Edge(te[0], te[1], headport="n", tailport="s", color="blue", label=str(cnts[i]))
    else:
      e = pydot.Edge(te[0], te[1], headport="n", tailport="s")
    graph.add_edge(e)

  print "drawing png"
  graph.write_png('/tmp/graph.png')
  

def get_blocks(flow):
  # look at addresses
  # if an address can accept control from two addresses, it starts a basic block
  # if an address can give control to two addresses, it ends a basic block
  #   so add those two addresses to the basic block breaker set

  # address = [all that lead into it]
  prev_map = {}
  next_map = {}

  # address
  prev = None
  next_instruction = None

  basic_block_starts = set()

  for (address, length, clnum) in flow:
    if next_instruction != None and next_instruction != address:
      # anytime we don't run the next instruction in sequence
      # this is a basic block starts
      # print next_instruction, address, data
      basic_block_starts.add(address)
      #print " ** BLOCK START ** "

    #print clnum, hex(address), length

    if address not in prev_map:
      prev_map[address] = set()
    if prev not in next_map:
      next_map[prev] = set()

    prev_map[address].add(prev)
    next_map[prev].add(address)
    prev = address
    next_instruction = address + length

  # accepts control from two addresses
  for a in prev_map:
    if len(prev_map[a]) > 1:
      basic_block_starts.add(a)
  # gives control to two addresses
  for a in next_map:
    if len(next_map[a]) > 1:
      for i in next_map[a]:
        basic_block_starts.add(i)


  # now with all the addresses that start basic blocks
  # we can break the changelists up based on it
  blocks = []
  cchange = None
  last = None

  for (address, length, clnum, ins) in flow:
    if cchange == None:
      cchange = (clnum, address)
    if address in basic_block_starts:
      blocks.append({'clstart': cchange[0], 'clend': last[0], 'start': cchange[1], 'end': last[1]})
      cchange = (clnum, address)
    last = (clnum, address)

  blocks.append({'clstart': cchange[0], 'clend': last[0], 'start': cchange[1], 'end': last[1]})
  return blocks

def do_function_analysis(flow):
  next_instruction = None

  fxn_stack = []
  cancel_stack = []
  cl_stack = []

  fxn = []

  for (address, length, clnum, ins) in flow:
    if address in cancel_stack:
      # reran this address, this isn't return
      idx = cancel_stack.index(address)
      fxn_stack = fxn_stack[0:idx]
      cancel_stack = cancel_stack[0:idx]
      cl_stack = cl_stack[0:idx]
      #print map(hex, fxn_stack), clnum, "cancel"
    if address in fxn_stack:
      idx = fxn_stack.index(address)
      fxn.append({"clstart":cl_stack[idx],"clend":(clnum-1)})
      fxn_stack = fxn_stack[0:idx]
      cancel_stack = cancel_stack[0:idx]
      cl_stack = cl_stack[0:idx]
      #print map(hex, fxn_stack), clnum, "return"
    elif next_instruction != None and next_instruction != address:
      fxn_stack.append(next_instruction)
      cancel_stack.append(last_instruction)
      cl_stack.append(clnum)
      #print map(hex, fxn_stack), clnum
    next_instruction = address + length
    last_instruction = address
  return fxn

def do_loop_analysis(blocks):
  #blocks = blocks[0:0x30]
  arr = []
  bb = []
  ab = []

  realblocks = []
  realtrace = []

  idx = 0
  for i in range(len(blocks)):
    h = hex(blocks[i]['start']) + "-" + hex(blocks[i]['end'])
    if h not in arr:
      realblocks.append({'start': blocks[i]['start'], 'end': blocks[i]['end'], 'idx': idx})
      idx += 1
      arr.append(h)
    realtrace.append(arr.index(h))
    bb.append(arr.index(h))
    ab.append(i)

  loops = []
  # write this n^2 then make it fast
  did_update = True
  while did_update:
    did_update = False
    for i in range(len(bb)):
      for j in range(1,i):
        # something must run 3 times to make it a loop
        if bb[i:i+j] == bb[i+j:i+j*2] and bb[i:i+j] == bb[i+j*2:i+j*3]:
          loopcnt = 1
          while bb[i+j*loopcnt:i+j*(loopcnt+1)] == bb[i:i+j]:
            loopcnt += 1
          #print "loop",bb[i:i+j],"@",i,"with count",loopcnt
          # document the loop
          loop = {"clstart":blocks[ab[i]]['clstart'], 
                  "clendone":blocks[ab[i+j-1]]['clend'],
                  "clend":blocks[ab[i+j*loopcnt]]['clend'],
                  "blockstart":ab[i],
                  "blockend":ab[i]+j-1,
                  "count": loopcnt}
          # remove the loop from the blocks
          bb = bb[0:i] + bb[i:i+j] + bb[i+j*loopcnt:]
          ab = ab[0:i] + ab[i:i+j] + ab[i+j*loopcnt:]
          print loop
          loops.append(loop)
          did_update = True
          break
      if did_update:
        break

  ret = []
  for i in ab:
    t = blocks[i]
    t["blockidx"] = i
    ret.append(t)
  return (ret, loops, realblocks, realtrace)

def get_depth(fxns, clnum):
  d = 0
  for f in fxns:
    if clnum >= f['clstart'] and clnum <= f['clend']:
      d += 1
  return d

def get_depth_map(fxns, maxclnum):
  dderiv = [0]*maxclnum
  for f in fxns:
    dderiv[f['clstart']] += 1
    dderiv[f['clend']] -= 1

  dmap = []
  thisd = 0
  for i in range(maxclnum):
    thisd += dderiv[i]
    dmap.append(thisd)
  return dmap

def get_instruction_flow(trace, program, minclnum, maxclnum):
  ret = []
  for i in range(minclnum, maxclnum):
    r = trace.db.fetch_changes_by_clnum(i, 1)
    if len(r) != 1:
      continue
    ins = ""
    if r[0]['address'] in program.instructions:
      ins = program.instructions[r[0]['address']]
    ret.append((r[0]['address'], r[0]['data'], r[0]['clnum'], ins))
      
  return ret

def get_hacked_depth_map(flow):
  return_stack = []
  ret = [0]
  for (address, length, clnum, ins) in flow:
    if address in return_stack:
      return_stack = return_stack[0:return_stack.index(address)]
    if ins[0:5] == "call " or ins[0:6] == "callq ":
      return_stack.append(address+length)
    #print return_stack
    ret.append(len(return_stack))
  return ret
      

def analyze(trace, program):
  minclnum = trace.db.get_minclnum()
  maxclnum = trace.db.get_maxclnum()
  if maxclnum > 10000:
    # don't analyze if the program is bigger than this
    return None
  
  flow = get_instruction_flow(trace, program, minclnum, maxclnum)

  #blocks = get_blocks(flow)
  #print blocks
  #draw_multigraph(blocks)

  #fxns = do_function_analysis(flow)
  #print fxns

  #dmap = get_depth_map(fxns, maxclnum)
  dmap = get_hacked_depth_map(flow)
  maxd = max(dmap)

  if maxd == 0:
    return None

  #print dmap
  #print maxclnum, maxd

  from PIL import Image   # sudo pip install pillow
  import base64
  import StringIO
  im = Image.new( 'RGB', (1, maxclnum), "black")
  px = im.load()

  for i in range(maxclnum-minclnum):
    c = int((dmap[i]*128.0)/maxd)
    #px[0, i] = (int((dmap[i]*255.0)/maxd), 0, 0)
    #px[0, i] = (c,c,c)
    px[0, i] = (0,c,c)

  #im = im.resize((50, 1000), Image.ANTIALIAS)
  buf = StringIO.StringIO()
  im.save(buf, format='PNG')

  dat = "data:image/png;base64,"+base64.b64encode(buf.getvalue())
  return dat
  
  #loops = do_loop_analysis(blocks)
  #print loops

if __name__ == "__main__":
  # can run standalone for testing
  t = qira_program.Trace("/tmp/qira_logs/0", 0, 4, 9, False)
  while not t.db.did_update():
    time.sleep(0.1)
  print "loaded"
  fake_program = qira_program.Program("/tmp/qira_binary", [])
  fake_program.qira_asm_file = open("/tmp/qira_asm", "r")
  qira_program.Program.read_asm_file(fake_program)
  analyze(t, fake_program)

