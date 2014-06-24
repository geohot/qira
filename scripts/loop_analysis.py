def do_loop_analysis(blocks):
  blocks = blocks[0:0x30]
  arr = []
  bb = []
  for b in blocks:
    h = hex(b['start']) + "-" + hex(b['end'])
    if h not in arr:
      arr.append(h)
    bb.append(arr.index(h))

  # write this n^2 then make it fast
  # something must run 3 times to make it a loop??
  for i in range(len(bb)):
    for j in range(1,i):
      if bb[i:i+j] == bb[i+j:i+j*2] and bb[i:i+j] == bb[i+j*2:i+j*3]:
        loopcnt = 1
        while bb[i+j*loopcnt:i+j*(loopcnt+1)] == bb[i:i+j]:
          loopcnt += 1
        print "loop",bb[i:i+j],"@",i,"with count",loopcnt



  print bb
  exit(0)
    
  

