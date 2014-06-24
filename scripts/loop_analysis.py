def do_loop_analysis(blocks):
  #blocks = blocks[0:0x30]
  arr = []
  bb = []
  ab = []
  for i in range(len(blocks)):
    h = hex(blocks[i]['start']) + "-" + hex(blocks[i]['end'])
    if h not in arr:
      arr.append(h)
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
  return (ret, loops)
  

