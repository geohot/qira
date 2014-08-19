stream = io.connect(STREAM_URL);

// *** the analysis overlay ***
var overlays = {};

Deps.autorun(function() { DA("regetting analysis pictures, should be PUSH");
  var maxclnum = Session.get("max_clnum");
  overlays = {};
  // TODO: only get the updated analysis
  for (i in maxclnum) {
    stream.emit('doanalysis', parseInt(i))
  }
});

function on_setpicture(msg) { DS("setpicture");
  //p(msg);
  forknum = msg['forknum'];
  overlays[forknum] = msg['data'];
  var vt = $('#vtimeline'+forknum);
  vt.css('background-image', "url('"+overlays[forknum]+"')");
} stream.on('setpicture', on_setpicture);

// *** functions for dealing with the zoom function ***

Meteor.startup(function() {
  $("#vtimelinebox")[0].addEventListener("mousewheel", function(e) {
    var max = abs_maxclnum(); if (max === undefined) return;
    var cview = Session.get("cview"); if (cview === undefined) return;
    var cscale = get_cscale(); if (cscale === undefined) return;
    var move = Math.round(cscale * 50.0); // 50 pixels
    // clamping
    if (e.wheelDelta > 0) {
      if (cview[0] - move < 0) move = cview[0];
      Session.set("cview", [cview[0] - move, cview[1] - move]);
    } else {
      if (cview[1] + move > max) move = max-cview[1];
      Session.set("cview", [cview[0] + move, cview[1] + move]);
    }
  });
  register_drag_zoom();
});

function register_drag_zoom() {
  function get_clnum(e) {
    if ($(".vtimeline").index(e.target) == -1 &&
        e.target !== $("#vtimelinebox")[0]) return undefined;
    var max = abs_maxclnum(); if (max === undefined) return;
    var cview = Session.get("cview"); if (cview === undefined) return;
    var cscale = get_cscale();
    if (cscale === undefined) return undefined;
    // fix for non full zoom
    var clnum = (e.pageY * cscale) + cview[0];
    var clret = Math.round(clnum);
    if (clret > max) clret = max;
    return clret;
  }
  function get_forknum(e) {
    var fn = e.target.id.split("vtimeline")[1];
    if (fn == "box") return -1;
    return parseInt(fn);
  }
  var down = -1;
  var downforknum = -1;
  $("#vtimelinebox").mousedown(function(e) {
    if (e.button == 1) { zoom_out_max(); }
    if (e.button != 0) return;
    var clnum = get_clnum(e);
    if (clnum === undefined) return;
    down = clnum;
    downforknum = get_forknum(e);
    return false;
  });
  $("#vtimelinebox").contextmenu(function(e) {
    // right click to delete forks
    forknum = get_forknum(e);
    if (forknum != -1) {
      stream.emit("deletefork", forknum);
      redraw_flags();
    }
    return false;
  });
  $("#vtimelinebox").mouseup(function(e) {
    p("mouseup");
    if (e.button != 0) return;
    var up = get_clnum(e);
    if (up === undefined) return;
    var forknum = get_forknum(e);
    if (down != -1) {
      // should check absolute length of drag, not clnums
      p("drag "+down+"-"+up);
      if (down == up) {
        if (forknum != -1) {
          Session.set("clnum", down);
          Session.set("forknum", forknum);
        }
      } else if (down < up) {
        Session.set("cview", [down, up]);
      } else if (down > up) {
        Session.set("cview", [up, down]);
      }
    }
    return false;
  });
}

// *** functions for flags ***

var flags = {};

function get_cscale() {
  var cview = Session.get("cview");
  if (cview === undefined) return;
  var range = cview[1] - cview[0];
  var box = $("#vtimelinebox");
  if (box.length == 0) return undefined;
  var working_height = box[0].offsetHeight - 100;
  //var scale = Math.ceil(range/working_height);
  var scale = range/working_height;
  /*var real_height = Math.ceil(range/scale);
  var vtimelines = $('.vtimeline');
  for (var i = 0; i < vtimelines.length; i++) {
    vtimelines[i].style.height = real_height + "px";
  }*/
  //p("working height is "+working_height+" scale is "+scale);
  return scale;
}

function redraw_vtimelines(scale) {
  var cview = Session.get("cview");
  if (cview === undefined) return;
  var maxclnum = Session.get("max_clnum");
  if (maxclnum === undefined) return;

  // delete old ones that don't have a maxclnum anymore
  $(".vtimeline").each(function(e) {
    var forknum = $(this)[0].id.split("vtimeline")[1];
    if (maxclnum[forknum] === undefined) {
      $(this).remove();
    }
  });


  remove_flags("zoom");
  for (forknum in maxclnum) {
    var vt = $('#vtimeline'+forknum);
    var max = maxclnum[forknum];

    if (overlays[forknum] !== undefined) vt.css('background-image', "url('"+overlays[forknum]+"')");
    else vt.css('background-image', "");
    var cscale = get_cscale();

    if (max[0] < cview[0] && cview[0] < max[1]) { add_flag("zoom", forknum, cview[0]); }
    if (max[0] < cview[1] && cview[1] < max[1]) { add_flag("zoom", forknum, cview[1]); }

    // so it looks like size is applied before position, hence we divide position by cscale
    //vt.css('background-size', "100% " + ((max[1]-max[0]) / cscale) + "px")
    //vt.css('background-position-y', -1*(cview[0]/cscale) + "px");
    vt.css('background-size', "100% " + (max[1] / cscale) + "px")
    vt.css('background-position-y', -1*((Math.max(max[0],cview[0])-max[0])/cscale) + "px");
    vt.css('background-repeat', "no-repeat");
    if (vt.length == 0) {
      $("#vtimelinebox").append($('<div class="vtimeline" id="vtimeline'+forknum+'"></div>'))
      vt = $('#vtimeline'+forknum);
    }

    var range = Math.min(max[1], cview[1]) - Math.max(max[0], cview[0]);
    range = Math.max(0, range);
    var topp = 0;
    if (maxclnum[forknum][0] > cview[0]) {
      topp = Math.ceil((maxclnum[forknum][0] - cview[0])/scale);
    }
    var real_height = Math.ceil(range/scale);

    vt[0].style.height = real_height + "px";
    vt[0].style.top = topp + "px";
  }
}

delete_all_forks = function() {
  for (forknum in Session.get('max_clnum')) {
    stream.emit("deletefork", parseInt(forknum));
  }
  redraw_flags();
};

function redraw_flags() {
  var cview = Session.get("cview");
  if (cview === undefined) return undefined;
  var maxclnum = Session.get("max_clnum");
  if (maxclnum === undefined) return;
  var cscale = get_cscale();
  if (cscale === undefined) return;
  //$(".flag").remove();
  redraw_vtimelines(cscale);
  var colors = {
    "bounds": "green",
    "change": "blue",
    "ciaddr": "#AA0000", // keep it alphabetical
    "daddrr": "#888800",
    "daddrw": "yellow",
    "slice": "#000088",
    "zoom": "gray"
  };
  var flags_out = {};
  for (arr in flags) {
    var classes = "flag";
    var forknum = parseInt(arr.split(",")[0]);
    var clnum = parseInt(arr.split(",")[1]);
    if (clnum < cview[0] || clnum > cview[1]) continue;
    sty = "";
    if (flags[arr].length == 0) continue;
    else if (flags[arr].length == 1) {
      var col = colors[flags[arr][0]];
      sty = "background-color:"+col+"; color:"+col;
    }
    else {
      sty = "background: linear-gradient(to right"
      var cols = flags[arr].sort()
      for (var i = 0; i < cols.length; i++) {
        sty += ","+colors[cols[i]];
      }
      sty += ")";
    }
    
    if (maxclnum[forknum] === undefined) continue;
    if (flags_out[forknum] === undefined) flags_out[forknum] = "";

    flags_out[forknum] += '<div id="flag'+clnum+'" class="flag" style="'+sty+'; margin-top: '+((clnum-Math.max(maxclnum[forknum][0], cview[0]))/cscale) + "px"+'">'+clnum+'</div>'
  }
  for (forknum in flags_out) {
    $('#vtimeline'+forknum).html(flags_out[forknum]);
  }
}

function add_flag(type, forknum, clnum) {
  var t = [forknum, clnum];
  if (flags[t] !== undefined) flags[t].push(type);
  else flags[t] = [type];
}

function remove_flags(type, forknum) {
  for (arr in flags) {
    var tforknum = parseInt(arr.split(",")[0]);
    if (forknum !== undefined && forknum != tforknum) continue;
    var index = flags[arr].indexOf(type);
    while (index != -1) {
      flags[arr].splice(index, 1)
      index = flags[arr].indexOf(type);
    }
    if (flags[arr].length == 0) delete flags[arr];
  }
}

// these are public functions, no var
go_to_flag = function (next, data) {
  var gclnum = Session.get("clnum");
  var gforknum = Session.get("forknum");
  //var idx = flags.indexOf((forknum, clnum));
  var cls = [gclnum];
  for (arr in flags) {
    var forknum = parseInt(arr.split(",")[0]);
    var clnum = parseInt(arr.split(",")[1]);
    if (clnum == gclnum) continue;
    if (data) {
      if (flags[arr].indexOf("daddrr") != -1 ||
          flags[arr].indexOf("daddrw") != -1) {
        if (forknum == gforknum) cls.push(clnum);
      }
    } else {
      if (flags[arr].indexOf("ciaddr") != -1) {
        if (forknum == gforknum) cls.push(clnum);
      }
    }
  }
  cls.sort(function(a, b){return a-b});
  var idx = cls.indexOf(gclnum);
  if (idx == -1) return;
  if (next) {
    if (idx+1 < cls.length) {
      Session.set("clnum", cls[idx+1])
    }
  } else {
    if (idx-1 >= 0) {
      Session.set("clnum", cls[idx-1])
    }
  }
};

Deps.autorun(function() { DA("calling zoom_out_max, confusing autorun");
  // false here forces update on max_clnum update
  zoom_out_max(false);
});

Deps.autorun(function() { DA("updating bounds flags");
  var maxclnum = Session.get("max_clnum");
  if (maxclnum === undefined) return;
  remove_flags("bounds");
  for (forknum in maxclnum) {
    forknum = parseInt(forknum);
    add_flag("bounds", forknum, maxclnum[forknum][0]);
    add_flag("bounds", forknum, maxclnum[forknum][1]);
  }
  redraw_flags();
});

Deps.autorun(function() { DA("adding current change flag");
  var forknum = Session.get("forknum");
  var clnum = Session.get("clnum");
  remove_flags("change");
  add_flag("change", forknum, clnum);
  redraw_flags();
});

Deps.autorun(function() { DA("emit getchanges for iaddr change");
  var maxclnum = Session.get('max_clnum');
  var cview = Session.get('cview');
  var iaddr = Session.get('iaddr');
  stream.emit('getchanges', -1, iaddr, 'I', cview)
});

Deps.autorun(function() { DA("emit getchanges for daddr change");
  var maxclnum = Session.get('max_clnum');
  var cview = Session.get('cview');
  var daddr = Session.get('daddr');
  stream.emit('getchanges', -1, daddr, 'L', cview)
  stream.emit('getchanges', -1, daddr, 'S', cview)
});

function on_changes(msg) { DS("changes");
  var types = {'I': 'ciaddr', 'L': 'daddrr', 'S': 'daddrw'};
  var forknum = Session.get("forknum");
  var clnums = msg['clnums'][forknum];
  var type = types[msg['type']];
  var clnum = Session.get('clnum');

  // this should probably only be for the IDA plugin
  if (msg['type'] == 'I' && clnums !== undefined && clnums.indexOf(clnum) == -1 && Session.get('dirtyiaddr') == true) {
    var closest = undefined;
    var diff = 0;
    // if these are instructions and the current clnum isn't in the list
    for (var i = 0; i < clnums.length; i++) {
      var ldiff = Math.abs(clnums[i] - clnum);
      if (closest == undefined || diff > ldiff) {
        closest = clnums[i];
        diff = ldiff;
      }
    }
    //p("nearest change is "+closest);
    if (closest !== undefined && closest !== clnum) {
      Session.set("clnum", closest);
    }
    Session.set("dirtyiaddr", false);
  }

  remove_flags(type);
  for (forknum in msg['clnums']) {
    clnums = msg['clnums'][forknum];
    for (var i = 0; i < clnums.length; i++) {
      add_flag(type, forknum, clnums[i]);
    }
  }
  redraw_flags();
} stream.on('changes', on_changes);


