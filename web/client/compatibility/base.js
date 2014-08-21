function p(a) { console.log(a); }
//function DA(a) { p("DA: "+a); }
//function DS(a) { p("DS: "+a); }
//function DH(a) { p("DH: "+a); }
function DA(a) {}
function DS(a) {}
function DH(a) {}

if (window.location.port == 3000) {
  // for meteor development
  STREAM_URL = "http://localhost:3002/qira";
} else {
  STREAM_URL = window.location.origin+"/qira";
}

// ** history ***
function push_history(reason, replace) {
  var json = {};
  // the three views
  json['cview'] = Session.get('cview');
  json['dview'] = Session.get('dview');
  json['sview'] = Session.get('sview');

  // any addresses that we navigated to in a reasonable way
  json['clnum'] = Session.get('clnum');
  json['daddr'] = Session.get('daddr');
  //json['iaddr'] = Session.get('iaddr');
  
  if (JSON.stringify(history.state) != JSON.stringify(json)) {
    if (replace == true) {
      DH("REPL " + JSON.stringify(json) + " from "+reason);
      history.replaceState(json, "qira", "");
    } else {
      DH("PUSH " + JSON.stringify(json) + " from "+reason);
      history.pushState(json, "qira", "");
    }
  }
}

window.onpopstate = function(e) {
  DH("POP  " + JSON.stringify(e.state));
  for (k in e.state) {
    if (Session.get(k) != e.state[k]) { 
      Session.set(k, e.state[k]);
    }
  }
};

// this deals with scrolling
var historyTimeout = undefined;
Deps.autorun(function() { DA("history");
  Session.get('cview'); Session.get('dview'); Session.get('sview');
  Session.get('clnum'); Session.get('daddr');
  window.clearTimeout(historyTimeout);
  window.setTimeout(function() { push_history("autorun"); }, 1000);
});

// ** end history ***

var escapeHTML = (function () {
  'use strict';
  var chr = { '"': '&quot;', '&': '&amp;', '<': '&lt;', '>': '&gt;' };
  return function (text) {
    return text.replace(/[\"&<>]/g, function (a) { return chr[a]; });
  };
}());

function highlight_addresses(a) {
  // no XSS :)
  var d = escapeHTML(a);
  var re = /0x[0123456789abcdef]+/g;
  var m = d.match(re);
  if (m !== null) {
    m = m.filter(function (v,i,a) { return a.indexOf(v) == i });
    m.map(function(a) { 
      var cl = get_data_type(a);
      if (cl == "") return;
      d = d.replace(a, "<span class='"+cl+"'>"+a+"</span>");
    });
  }
  // does this work outside templates?
  return d;
}

function get_data_type(v) {
  if (typeof v == "number") v = hex(v);
  // haxx
  var pmaps = Session.get('pmaps');
  var a = pmaps[bn_round(v, 3)];
  if (a === undefined) return "";
  else return "data"+a;
}

function update_dview(addr) {
  Session.set('daddr', addr);
  Session.set('dview', bn_add(bn_round(addr, 1), -0x20));
  push_history("update dview");
}

function update_iaddr(addr) {
  Session.set("iaddr", addr);
  Session.set("dirtyiaddr", true);
  push_history("update iaddr");
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

function rehighlight() {
  var clnum = Session.get("clnum");
  var iaddr = Session.get("iaddr");
  var daddr = Session.get("daddr");
  $(".autohighlight").removeClass("autohighlight");
  $(".clnum_"+clnum).addClass("autohighlight");
  $(".iaddr_"+iaddr).addClass("autohighlight");
  $(".daddr_"+daddr).addClass("autohighlight");
  $(".data_"+daddr).addClass("autohighlight");
}

Deps.autorun(function() { DA("rehighlight");
  rehighlight();
});


function update_maxclnum(clnum) {
  //p("update maxclnum "+clnum);
  var old_maxclnum = Session.get("max_clnum");
  Session.set("max_clnum", clnum);

  // if we are zoomed out, zoom out all the way
  var cview = Session.get("cview")
  if (cview == undefined || cview[0] == 0) zoom_out_max(false);

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
  push_history("zoom out cview");
}

