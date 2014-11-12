import idaapi
import json

# all functions from all segments
all_functions = []
for ea in Segments():
    all_functions.append([x for x in Functions(SegStart(ea), SegEnd(ea))])

fn_json = json.dumps([item for sublist in all_functions for item in sublist])

with open(idaapi.get_input_file_path()+".ida_info") as f:
    f.write(fn_json)

#starter code for getting basic blocks when we need them
"""
f = idaapi.FlowChart(idaapi.get_func(function_ea))
'endEA', 'id', 'preds', 'startEA', 'succs', 'type'
print "preds"
for block in f:
print dir(block)
print "%x - %x [%d]:" % (block.startEA, block.endEA, block.id)
for succ_block in block.succs():
    print "  %x - %x [%d]:" % (succ_block.startEA, succ_block.endEA, succ_block.id)

for pred_block in block.preds():
    print "  %x - %x [%d]:" % (pred_block.startEA, pred_block.endEA, pred_block.id)
"""
