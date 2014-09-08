// static stuff

stream = io.connect(STREAM_URL);

Deps.autorun(function() { DA("update static view");
  var iaddr = Session.get('iaddr');
  if (iaddr === undefined) return;
  stream.emit('getfunc', iaddr);
});

/*$(function() {
  $("#staticpanel").css("display", "none");
});*/

function on_tags(addrs) { DS("tags"); 
  //p(addrs);
  var idump = "";
  idump += '<div class="basicblock">';
  for (var i=0;i<addrs.length;i++) {
    var ins = addrs[i];
    idump += '<div class="instruction">';
    idump += '<span class="hexdumpdatainstruction iaddr iaddr_'+ins.address+'">'+ins.address+'</span> '+
    //'<div class="instructiondesc">'+hex(ins.flags)+'</div> '+
    '<div class="instructiondesc">'+ins.instruction+'</div>';
    idump += '</div>';
    if (ins.semantics !== undefined && ins.semantics.indexOf("endbb") != -1 && i+1 != addr.length) {
      idump += '</div><div class="basicblock">';
    }
  }
  idump += '</div>';
  $("#static").html(idump);
  rehighlight();
} stream.on('tags', on_tags);

