stream = io.connect(STREAM_URL);

// *** the analysis overlay ***

Deps.autorun(function() {
  var maxclnum = Session.get("max_clnum");
  for (i in maxclnum) {
    stream.emit('doanalysis', parseInt(i))
  }
});

var overlays = {};

stream.on('setpicture', function(msg) {
  p(msg);
  forknum = msg['forknum'];
  overlays[forknum] = msg['data'];
  var vt = $('#vtimeline'+forknum);
  vt.css('background-image', "url('"+overlays[forknum]+"')");
});

// *** functions for dealing with the zoom function ***

Meteor.startup(function() {
  $("#vtimelinebox")[0].addEventListener("mousewheel", function(e) {
    var max = abs_maxclnum(); if (max === undefined) return;
    var cview = Session.get("cview"); if (cview === undefined) return;
    var cscale = get_cscale(); if (cscale === undefined) return;
    var move = Math.round(cscale * 50.0); // 50 pixels
    // clamping
    if (e.wheelDelta < 0) {
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
    if (e.target.id == "trash") return -1;
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
  $("#vtimelinebox").mouseup(function(e) {
    p("mouseup");
    if (e.button != 0) return;
    if (e.target.id == "trash" && downforknum != -1) {
      stream.emit("deletefork", downforknum);
      redraw_flags();
      return;
    }

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
    var topp = 0;
    if (maxclnum[forknum][0] > cview[0]) {
      topp = Math.ceil((maxclnum[forknum][0] - cview[0])/scale);
    }
    var real_height = Math.ceil(range/scale);

    vt[0].style.height = real_height + "px";
    vt[0].style.top = topp + "px";
  }
}

function redraw_flags() {
  var cview = Session.get("cview");
  if (cview === undefined) return undefined;
  var maxclnum = Session.get("max_clnum");
  if (maxclnum === undefined) return;
  var cscale = get_cscale();
  if (cscale === undefined) return;
  $(".flag").remove();
  redraw_vtimelines(cscale);
  var colors = {
    "bounds": "green",
    "change": "blue",
    "ciaddr": "#AA0000", // keep it alphabetical
    "daddrr": "#888800",
    "daddrw": "yellow",
    "zoom": "gray"
  };
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

    var flag = $('<div id="flag'+clnum+'" class="flag" style="'+sty+'">'+clnum+'</div>');
    flag[0].style.marginTop = ((clnum-Math.max(maxclnum[forknum][0], cview[0]))/cscale) + "px";
    flag.click(function(cln) { Session.set("forknum", cln[0]); Session.set("clnum", cln[1]); }.bind(undefined, [forknum, clnum]));
    $('#vtimeline'+forknum).append(flag);
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

Deps.autorun(function() {
  // false here forces update on max_clnum update
  zoom_out_max(false);
});

Deps.autorun(function() {
  /*var cview = Session.get("cview");
  if (cview === undefined) return undefined;
  add_flag("bounds", 0, cview[0]);
  add_flag("bounds", 0, cview[1]);*/
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

Deps.autorun(function() {
  var forknum = Session.get("forknum");
  var clnum = Session.get("clnum");
  remove_flags("change");
  add_flag("change", forknum, clnum);
  redraw_flags();
});

Deps.autorun(function() {
  //var forknum = Session.get("forknum");
  var iaddr = Session.get('iaddr');
  var maxclnum = Session.get('max_clnum');
  stream.emit('getchanges', -1, iaddr, 'I')
});

Deps.autorun(function() {
  //var forknum = Session.get("forknum");
  var daddr = Session.get('daddr');
  var maxclnum = Session.get('max_clnum');
  stream.emit('getchanges', -1, daddr, 'L')
  stream.emit('getchanges', -1, daddr, 'S')
});

stream.on('changes', function(msg) {
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
});

