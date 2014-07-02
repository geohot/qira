Meteor.startup(function() {

  /*$("#vtimeline").click(function(e) {
    if (e.target !== $("#vtimeline")[0]) return;
    var cscale = get_cscale();
    if (cscale == undefined) return;
    Session.set("clnum", e.offsetY * cscale);
  });*/

  $("#vtimeline")[0].addEventListener("mousewheel", function(e) {
    var max = Session.get("max_clnum"); if (max === undefined) return;
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

function zoom_out_max(dontforce) {
  var max = Session.get("max_clnum");
  if (max === undefined) return;
  if (dontforce === true)  Session.setDefault("cview", [0, max]);
  else Session.set("cview", [0, max]);
}

function register_drag_zoom() {
  function get_clnum(e) {
    if (e.target !== $("#vtimeline")[0]) return undefined;
    var cview = Session.get("cview");
    if (cview === undefined) return undefined;
    var cscale = get_cscale();
    if (cscale === undefined) return undefined;
    // fix for non full zoom
    var clnum = (e.offsetY * cscale) + cview[0];
    return Math.round(clnum);
  }
  var down = -1;
  $("#vtimeline").mousedown(function(e) {
    if (e.button == 1) { zoom_out_max(); }
    if (e.button != 0) return;
    var clnum = get_clnum(e);
    if (clnum === undefined) return;
    down = clnum;
    return false;
  });
  $("#vtimeline").mouseup(function(e) {
    if (e.button != 0) return;
    var up = get_clnum(e);
    if (up === undefined) return;
    if (down != -1) {
      p("drag "+down+"-"+up);
      if (down == up) {
        Session.set("clnum", down);
      } else if (down < up) {
        Session.set("cview", [down, up]);
      } else if (down > up) {
        Session.set("cview", [up, down]);
      }
    }
    return false;
  });
}

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
  var real_height = Math.ceil(range/scale);
  $("#vtimeline")[0].style.height = real_height + "px";
  //p("working height is "+working_height+" scale is "+scale);
  return scale;
}

function redraw_flags() {
  var cview = Session.get("cview");
  if (cview === undefined) return undefined;
  var cscale = get_cscale();
  if (cscale === undefined) return;
  $(".flag").remove();
  var colors = {
    "bounds": "green",
    "change": "blue",
    "ciaddr": "#AA0000", // keep it alphabetical
    "daddrr": "#888800",
    "daddrw": "yellow"
  };
  for (clnum in flags) {
    var classes = "flag";
    clnum = parseInt(clnum);
    if (clnum < cview[0] || clnum > cview[1]) continue;
    sty = "";
    if (flags[clnum].length == 0) continue;
    else if (flags[clnum].length == 1) {
      var col = colors[flags[clnum][0]];
      sty = "background-color:"+col+"; color:"+col;
    }
    else {
      sty = "background: linear-gradient(to right"
      var cols = flags[clnum].sort()
      for (var i = 0; i < cols.length; i++) {
        sty += ","+colors[cols[i]];
      }
      sty += ")";
    }

    var flag = $('<div id="flag'+clnum+'" class="flag" style="'+sty+'">'+clnum+'</div>');
    flag[0].style.marginTop = ((clnum-cview[0])/cscale) + "px";
    flag.click(function(cln) { Session.set("clnum", cln); }.bind(undefined, clnum));
    $('#vtimeline').append(flag);
  }
}

function add_flag(type, clnum) {
  if (flags[clnum] !== undefined) flags[clnum].push(type);
  else flags[clnum] = [type];
}

function remove_flags(type) {
  for (clnum in flags) {
    var index = flags[clnum].indexOf(type);
    while (index != -1) {
      flags[clnum].splice(index, 1)
      index = flags[clnum].indexOf(type);
    }
    if (flags[clnum].length == 0) delete flags[clnum];
  }
}

Deps.autorun(function() {
  // false here forces update on max_clnum update
  zoom_out_max(false);
});

Deps.autorun(function() {
  var cview = Session.get("cview");
  remove_flags("bounds");
  add_flag("bounds", cview[0]);
  add_flag("bounds", cview[1]);
  redraw_flags();
});

Deps.autorun(function() {
  var clnum = Session.get("clnum");
  remove_flags("change");
  add_flag("change", clnum);
  redraw_flags();
});

Deps.autorun(function() {
  var clnum = Session.get("clnum");
  var iaddr = Session.get('iaddr');
  remove_flags("ciaddr");
  Change.find({address: iaddr, type: "I"}).forEach(function(x) {
    add_flag("ciaddr", x.clnum);
  });
  redraw_flags();
});

Deps.autorun(function() {
  var clnum = Session.get("clnum");
  var daddr = Session.get('daddr');
  remove_flags("daddrr");
  remove_flags("daddrw");
  //Change.find({address: daddr, $or: [{type: "L"}, {type: "S"}] }).forEach(function(x) {
  Change.find({address: daddr}).forEach(function(x) {
    if (x.type == "L") add_flag("daddrr", x.clnum);
    if (x.type == "S") add_flag("daddrw", x.clnum);
  });
  redraw_flags();
});

