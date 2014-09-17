// static stuff

stream = io.connect(STREAM_URL);

Deps.autorun(function() { DA("update static view");
  var iview = Session.get('iview');
  var flat = Session.get('flat');
  if (iview === undefined) return;
  stream.emit('getstaticview', iview, flat, [-15,40]);
});

/*$(function() {
  $("#staticpanel").css("display", "none");
});*/


// TODO: this code is replicated in idump.js
function instruction_html_from_tags(ins) {
  var idump = '<div class="instruction">';
  idump += '<span class="insaddr datainstruction addr addr_'+ins.address+'">'+ins.address+'</span> '+
  //'<div class="instructiondesc">'+hex(ins.flags)+'</div> '+
  '<div class="instructiondesc">'+highlight_instruction(ins.instruction)+'</div> '+
  '<span class="comment comment_'+ins.address+'">'+(ins.comment !== undefined ? "; "+ins.comment : "")+'</span>';
  idump += '</div>';
  return idump;
}

function display_flat(addrs) {
  //p(addrs);
  var idump = '<div class="flat">';
  for (var i=0;i<addrs.length;i++) {
    idump += instruction_html_from_tags(addrs[i]);
  }
  idump += '</div>';
  $("#staticpanel").html(idump);
}

function on_tags(addrs, fxn) { DS("tags"); 
  if (!fxn) {
    display_flat(addrs);
  } else {
    var graph = new Graph();

    //p(addrs);

    // this renders all the graph vertices
    var idump = "";
    var in_basic_block = false;
    var last_basic_block = false;
    var last_block_has_flow = false;
    var cnt = 0;

    function pushBlock() {
      if (last_basic_block != false) {
        var dom = $('<div class="basicblock" id="bb_'+ins.address+'">');
        dom.html(idump);
        idump = "";
        cnt = 0;
        graph.addVertex(last_basic_block, cnt, dom[0]);
      }
    }

    for (var i=0;i<addrs.length;i++) {
      var ins = addrs[i];
      if (ins.scope == undefined) continue;
      if (in_basic_block == false) {
        // accepts control from previous instruction
        if (ins.flags & 0x10000 && last_basic_block != false) {
          var color = "blue";
          if (last_block_has_flow) {
            color = "red";
          }
          graph.addEdge(last_basic_block, ins.address, color);
        }
        in_basic_block = ins.address;
      }
      if (ins.instruction === undefined) {
        ins.instruction = "undefined";
      }
      cnt += 1;
      idump += instruction_html_from_tags(ins);

      if (ins.semantics !== undefined && ins.semantics.indexOf("endbb") != -1) {
        last_basic_block = in_basic_block;
        //p(ins.flow);
        last_block_has_flow = false;
        for (var j = 0; j < ins.flow.length; j++) {
          graph.addEdge(last_basic_block, ins.flow[j], "green");
          last_block_has_flow = true;
        }
        pushBlock();
        in_basic_block = false;
      }
    }

    if (in_basic_block) pushBlock();

    graph.assignLevels();
    graph.render();
  }

  rehighlight();
  replace_names();
} stream.on('tags', on_tags);

