stream = io.connect(STREAM_URL);

// arch is public data
arch = undefined;
function on_arch(msg) { DS("arch");
  //p(msg);
  arch = msg;
} stream.on("arch", on_arch);

function on_instructions(msg) { DS("instructions");
  var clnum = Session.get("clnum");
  var idump = "";
  var addrs = [];
  for (var i = 0; i<msg.length;i++) {
    var ins = msg[i];

    if (ins.clnum === clnum) {
      Session.set('iaddr', ins.address);
      Session.set('iview', ins.address);
    }

    if (ins.name == undefined) {
      ins.name = "";
    }

    // track the addresses
    addrs.push([ins.clnum-clnum, ins.address]);

    // compute the dynamic stuff
    // TODO: hacks for trail stuff working
    if (i >= 10) {
      idump +=
         '<div class="instruction" style="margin-left: '+(ins.depth*10)+'px">'+
          '<div class="change '+(ins.slice ? "halfhighlight": "")+' clnum clnum_'+ins.clnum+'">'+ins.clnum+'</div> '+
          '<span class="insaddr datainstruction addr addr_'+ins.address+'">'+ins.address+'</span> '+
          '<div class="instructiondesc">'+highlight_instruction(ins.instruction)+'</div> '+
          '<span class="comment comment_'+ins.address+'">'+(ins.comment !== undefined ? "; "+ins.comment : "")+'</span>'+
        '</div>';
    }
  }
  Session.set('trail', addrs);
  $('#idump').html(idump);
  rehighlight();
  replace_names();
} stream.on('instructions', on_instructions);

Deps.autorun(function() { DA("emit getinstructions");
  var forknum = Session.get("forknum");
  var clnum = Session.get("clnum");
  var maxclnum = Session.get("max_clnum");
  if (maxclnum === undefined) return;
  maxclnum = maxclnum[forknum];

  // correct place for this clamp?
  if (clnum > maxclnum[1]) { clnum = maxclnum[1]; Session.set("clnum", clnum); }
  if (clnum < maxclnum[0]) { clnum = maxclnum[0]; Session.set("clnum", clnum); }

  // TODO: make this clean
  var size = get_size("#idump");
  var end = Math.min(maxclnum[1]+1, clnum+size-6);
  var start = Math.max(maxclnum[0], end-size);
  if (maxclnum[0] > (end-size)) end += maxclnum[0] - (end-size) + 1;

  stream.emit('getinstructions', forknum, clnum, start-10, end);
});

