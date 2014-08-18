if (window.location.port == 3000) {
  // for meteor development
  STREAM_URL = "http://localhost:3002/qira";
} else {
  STREAM_URL = window.location.origin+"/qira";
}

function p(a) { console.log(a); }

function fhex(a) {
  return parseInt(a, 16);
}

function hex(a) {
  if (a == undefined) {
    return "";
  } else {
    if (a < 0) a += 0x100000000;
    return "0x"+a.toString(16);
  }
}

// s is a hex number
// num is the number of digits to round off
function string_round(s, num) {
  if ((s.length-2) <= num) {
    ret = "0x0";
  } else {
    var ret = s.substring(0, s.length-num);
    for (var i = 0; i < num; i++) {
      ret += "0";
    }
  }
  return ret;
}

function string_add(s, num) {
  // still wrong for big numbers
  return hex(fhex(s)+num);
}

function get_data_type(v) {
  if (typeof v == "number") v = hex(v);
  //if (typeof v == "string") v = parseInt(v, 16);
  //var a = pmaps[v - v%0x1000];

  // haxx
  var pmaps = Session.get('pmaps');
  var a = pmaps[string_round(v, 3)];
  if (a === undefined) return "";
  else return "data"+a;
}

function highlight_addresses(a) {
  // no XSS :)
  var d = UI.toHTML(a);
  var re = /0x[0123456789abcdef]+/g;
  var m = d.match(re);
  if (m !== null) {
    m = m.filter(function (v,i,a) { return a.indexOf(v) == i });
    m.map(function(a) { 
      var cl = get_data_type(a);
      if (cl == "") return;
      d = d.replace(a, "<span class='h"+cl+"'>"+a+"</span>");
    });
  }
  return new Handlebars.SafeString(d);
}

function update_dview(addr) {
  Session.set('daddr', addr);
  Session.set('dview', string_add(string_round(addr, 1), -0x20));
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
    var daddr = e.target.innerHTML;
    update_dview(daddr);
  },
  'click .datainstruction': function(e) {
    var daddr = e.target.innerHTML;
    update_dview(daddr);
  },
  'contextmenu .datainstruction': function(e) {
    // right click to follow in instruction dump
    // add menu maybe?
    var iaddr = e.target.innerHTML;
    Session.set("dirtyiaddr", true);
    Session.set('iaddr', iaddr);
    return false;
  },
  'click .data': function(e) {
    var daddr = e.target.getAttribute('id').split("_")[1];
    Session.set('daddr', daddr);
  },
  'click .register': function(e) {
    // the registers are in the zero page
    Session.set('daddr', hex(this.address));
  }
};

// uniform events everywhere
// ugh duplicated code, i'm bad at javascript
var basedblevents = {
  'mousedown .datamemory': function(e) { return false; },
  'mousedown .datainstruction': function(e) { return false; },
  // ugh highlights
  'dblclick .datamemory': function(e) {
    var daddr = e.target.innerHTML;
    update_dview(daddr);
  },
  'dblclick .datainstruction': function(e) {
    var daddr = e.target.innerHTML;
    update_dview(daddr);
  },
  'contextmenu .datainstruction': function(e) {
    // right click to follow in instruction dump
    // add menu maybe?
    var iaddr = e.target.innerHTML;
    Session.set("dirtyiaddr", true);
    Session.set('iaddr', iaddr);
    return false;
  },
  'click .data': function(e) {
    var daddr = e.target.getAttribute('id').split("_")[1];
    Session.set('daddr', daddr);
  },
};

