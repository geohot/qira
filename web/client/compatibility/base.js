function p(a) { console.log(a); }

pmaps = {}
function get_data_type(v) {
  if (typeof v == "string") v = parseInt(v, 16);
  var a = pmaps[v - v%0x1000];
  if (a === undefined) return "";
  else return "data"+a;
}

function hex(a) {
  if (a == undefined) {
    return "";
  } else {
    if (a < 0) a += 0x100000000;
    return "0x"+a.toString(16);
  }
}

function update_dview(addr) {
  Session.set('daddr', addr);
  Session.set('dview', (addr-0x20)-(addr-0x20)%0x10);
}

function abs_maxclnum() {
  var maxclnum = Session.get("max_clnum")
  var ret = undefined;
  for (i in maxclnum) {
    if (ret == undefined || ret < maxclnum[i][1]) {
      ret = maxclnum[i][1];
    }
  }
  return ret;
}

function update_maxclnum(clnum) {
  p("update maxclnum "+clnum);
  var old_maxclnum = Session.get("max_clnum");
  Session.set("max_clnum", clnum);

  Session.setDefault("forknum", 0);
  var forknum = Session.get("forknum");

  if (clnum[forknum] === undefined) return;
  Session.setDefault("clnum", clnum[forknum][1]);

  if (old_maxclnum === undefined || old_maxclnum[forknum] === undefined) return;
  if (old_maxclnum[forknum][1] == Session.get("clnum")) {
    // track the max changelist if you have it selected
    Session.set("clnum", clnum[forknum][1]);
  }
}

function zoom_out_max(dontforce) {
  var max = abs_maxclnum();
  if (max === undefined) return;
  if (dontforce === true)  Session.setDefault("cview", [0, max]);
  else Session.set("cview", [0, max]);
}

var baseevents = {
  'click .datamemory': function(e) {
    var daddr = parseInt(e.target.innerHTML, 16);
    update_dview(daddr);
  },
  'click .datainstruction': function(e) {
    var iaddr = parseInt(e.target.innerHTML, 16);
    Session.set("dirtyiaddr", true);
    Session.set('iaddr', iaddr);
  },
};

