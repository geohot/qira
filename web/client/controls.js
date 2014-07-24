stream = io.connect("http://localhost:3002/qira");

Template.controls.clnum = function() {
  return Session.get("clnum");
};

Template.controls.forknum = function() {
  return Session.get("forknum");
};

Template.controls.iaddr = function() {
  return hex(Session.get("iaddr"));
};

Template.controls.daddr = function() {
  return hex(Session.get("daddr"));
};

Template.controls.events = {
  'change #control_clnum': function(e) {
    Session.set("clnum", parseInt(e.target.value));
  },
  'change #control_forknum': function(e) {
    Session.set("forknum", parseInt(e.target.value));
  },
  'change #control_iaddr': function(e) {
    Session.set("iaddr", parseInt(e.target.value, 16));
  },
  'change #control_daddr': function(e) {
    update_dview(parseInt(e.target.value, 16));
  },
  'click #control_fork': function(e) {
    var clnum = Session.get("clnum");
    var forknum = Session.get("forknum");
    stream.emit('forkat', forknum, clnum);
  },
  'click #control_analysis': function(e) {
    var is_analyzing = Session.get("is_analyzing");
    if (is_analyzing) {
      Session.set("is_analyzing", false);
    } else {
      Session.set("is_analyzing", true);
    }
  }
};

Deps.autorun(function() {
  var is_analyzing = Session.get("is_analyzing");
  var maxclnum = Session.get("max_clnum");
  if (is_analyzing) {
    $('#control_analysis').addClass("highlight");
    for (i in maxclnum) {
      stream.emit('doanalysis', parseInt(i))
    }
  } else {
    $('#control_analysis').removeClass("highlight");
    $(".vtimeline").each(function(id) {
      $(this)[0].style.backgroundImage = "";
    });
  }
});

stream.on('setpicture', function(msg) {
  p(msg);
  var id = $("#vtimeline"+msg['forknum'])[0]
  id.style.backgroundImage = "url('"+msg['data']+"')";
  id.style.backgroundSize = "contain";
});

// keyboard shortcuts
window.onkeydown = function(e) {
  //p(e.keyCode);
  if (e.keyCode == 37) {
    Session.set("forknum", Session.get("forknum")-1);
  } else if (e.keyCode == 39) {
    Session.set("forknum", Session.get("forknum")+1);
  } else if (e.keyCode == 38) {
    Session.set("clnum", Session.get("clnum")-1);
  } else if (e.keyCode == 40) {
    Session.set("clnum", Session.get("clnum")+1);
  } else if (e.keyCode == 90) {
    zoom_out_max();
  } else if (e.keyCode == 27) {
    history.back();
  }
};

// don't pull the window
//window.onmousewheel = function() { return false; }

