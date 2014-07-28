if (window.location.port == 3000) {
  // for meteor development
  STREAM_URL = "http://localhost:3002/qira";
} else {
  STREAM_URL = window.location.origin+"/qira";
}

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


// uniform events everywhere
var baseevents = {
  'mousedown .datamemory': function(e) { return false; },
  'mousedown .datainstruction': function(e) { return false; },
  // ugh highlights
  'click .datamemory': function(e) {
    var daddr = parseInt(e.target.innerHTML, 16);
    update_dview(daddr);
  },
  'click .datainstruction': function(e) {
    var daddr = parseInt(e.target.innerHTML, 16);
    update_dview(daddr);
  },
  'contextmenu .datainstruction': function(e) {
    // right click to follow in instruction dump
    // add menu maybe?
    var iaddr = parseInt(e.target.innerHTML, 16);
    Session.set("dirtyiaddr", true);
    Session.set('iaddr', iaddr);
    return false;
  },
  'click .data': function(e) {
    var daddr = parseInt(e.target.getAttribute('daddr'));
    Session.set('daddr', daddr);
  },
  'click .register': function(e) {
    // the registers are in the zero page
    Session.set('daddr', this.address);
  }
};

// uniform events everywhere
// ugh duplicated code, i'm bad at javascript
var basedblevents = {
  'mousedown .datamemory': function(e) { return false; },
  'mousedown .datainstruction': function(e) { return false; },
  // ugh highlights
  'dblclick .datamemory': function(e) {
    var daddr = parseInt(e.target.innerHTML, 16);
    update_dview(daddr);
  },
  'dblclick .datainstruction': function(e) {
    var daddr = parseInt(e.target.innerHTML, 16);
    update_dview(daddr);
  },
  'contextmenu .datainstruction': function(e) {
    // right click to follow in instruction dump
    // add menu maybe?
    var iaddr = parseInt(e.target.innerHTML, 16);
    Session.set("dirtyiaddr", true);
    Session.set('iaddr', iaddr);
    return false;
  },
  'click .data': function(e) {
    var daddr = parseInt(e.target.getAttribute('daddr'));
    Session.set('daddr', daddr);
  },
};

