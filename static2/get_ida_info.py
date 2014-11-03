import idaapi
import json

# Loop through all the functions
for ea in Segments():
    for function_ea in Functions(SegStart(ea), SegEnd(ea)):
        print json.dumps(x for x in function_ea)
        #print GetFunctionName(function_ea)
        #for getting basic blocks when we need them
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
