regcolors = ['#60AE3F', '#723160', '#2A80A2', '#9E66BD', '#BC8D6B', '#3F3EAC', '#BC48B8', '#6B7C76', '#5FAC7F', '#A69B71', '#874535', '#AD49BF', '#73356F', '#55A4AC', '#988590', '#505C62', '#404088', '#56726B', '#BAAC62', '#454066', '#BCAEAA', '#4E7F6A', '#3960B5', '#295231', '#3B37A5', '#6A9191', '#976394', '#7F957D', '#B7AFBD', '#BD4A70', '#A35169', '#2F2D95', '#8879A8', '#8D3A8E', '#636E7C', '#82688D', '#9FA893', '#2A6885', '#812C87', '#568E71', '#6FA0B2', '#7B7928', '#57BD86', '#6BBC9A', '#807FB3', '#922AAD', '#AB5D98', '#9C943A', '#796880', '#294870', '#528054', '#4ABBA2', '#87437B', '#AA4E73', '#2893AC', '#5AA383', '#A5714D', '#648186', '#68BA37', '#466A89', '#5CB871', '#3D8267', '#28B930', '#5E6C6F', '#5C6772', '#389E58', '#34B69B', '#3CA46A', '#4F4691', '#4D48A1', '#836CB1', '#2B6948', '#4F42BB', '#549B68', '#69B563', '#B39F5C', '#A37841', '#7858B4', '#577244', '#2B7DAD'];

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
  json['iview'] = Session.get('iview');

  // any addresses that we navigated to in a reasonable way
  json['clnum'] = Session.get('clnum');
  json['daddr'] = Session.get('daddr');
  json['iaddr'] = Session.get('iaddr');
  
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

function get_data_type(v) {
  if (typeof v == "number") throw "numbers no longer supported here";
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

function update_iaddr(addr, dirty) {
  if (dirty === undefined) dirty = true;
  Session.set("iaddr", addr);
  if (dirty) {
    Session.set("dirtyiaddr", true);
    Session.set("iview", addr);
  }
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

function sync_tags_request(addrs) {
  var req = new XMLHttpRequest();
  req.open('POST', '/gettagsa', false);
  req.send(JSON.stringify(addrs));
  return JSON.parse(req.response);
}

function async_tags_request(addrs, cb) {
  var req = new XMLHttpRequest();
  req.open('POST', '/gettagsa', true);
  req.onreadystatechange = function() {
    if (req.readyState == 4 && req.status == 200) {
      cb(JSON.parse(req.response));
    }
  }
  req.send(JSON.stringify(addrs));
}

