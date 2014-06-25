Change = new Meteor.Collection("change");
Blocks = new Meteor.Collection("blocks");
Loops = new Meteor.Collection("loops");
Fxns = new Meteor.Collection("fxns");
Program = new Meteor.Collection("program");

// bitops make numbers negative


Meteor.startup(function () {
  Session.setDefault("collapsed", []);
});

window.onmousewheel = function(e) {
  if (e.target.id == "cfg" || $(e.target).parents("#cfg").length > 0) {
    if (e.wheelDelta < 0) {
      Session.set('clnum', Session.get('clnum')+1);
    } else if (e.wheelDelta > 0) {
      Session.set('clnum', Session.get('clnum')-1);
    }
  } else if (e.target.id == "hexdump" || $(e.target).parents("#hexdump").length > 0) {
    if (e.wheelDelta < 0) {
      Session.set('daddr', Session.get('daddr')+0x10);
    } else if (e.wheelDelta > 0) {
      Session.set('daddr', Session.get('daddr')-0x10);
    }
  }
};

var socket = undefined;
function do_socket(callme) {
  if (socket == undefined) {
    p('connecting');
    socket = io.connect('http://localhost:3002');
    socket.on('connect', function() {
      p("socket connected");
      callme();
    });
    socket.on('memory', function(msg) {
      //p(msg);
      var dat = atob(msg['raw'])
      // render the hex editor
      var addr = msg['address'];
      html = "<table><tr>";
      for (var i = 0; i < dat.length; i++) {
        if ((i&0xF) == 0) html += "</tr><tr><td>"+hex(addr+i)+":</td>";
        if ((i&0x3) == 0) html += "<td></td>";
        var me = dat.charCodeAt(i).toString(16);
        if (me.length == 1) me = "0" + me;
        if (addr+i == Session.get('daddr')) {
          html += '<td class="highlight">'+me+"</td>";
        } else {
          html += "<td>"+me+"</td>";
        }
      }
      html += "</tr></table>";
      $("#hexdump")[0].innerHTML = html;
    });
    socket.on('registers', function(msg) {
      //p(msg);
      html = "";
      for (i in msg) {
        html += "<div class=reg daddr="+msg[i]+">"+i+": "+hex(msg[i])+"</div>";
      }
      $("#regviewer")[0].innerHTML = html;
    });
  } else {
    callme();
  }
}

Deps.autorun(function() {
  var daddr = Session.get('daddr');
  var clnum = Session.get('clnum');
  do_socket(function() {
    socket.emit('getmemory',
      {"clnum":clnum-1, "address":(daddr-0x20)-(daddr-0x20)%0x10, "len":0x100});
  });
});

Deps.autorun(function() {
  var clnum = Session.get('clnum');
  do_socket(function() {
    socket.emit('getregisters', {"clnum":clnum-1});
  });
});

// there should be a library for this
Deps.autorun(function() {
  var json = {};
  // for dep tracking, can't use keys
  json['max_clnum'] = Session.get('max_clnum');
  json['clnum'] = Session.get('clnum');
  json['iaddr'] = Session.get('iaddr');
  json['daddr'] = Session.get('daddr');
  json['collapsed'] = Session.get('collapsed');
  var hash = JSON.stringify(json);
  //p("updating hash to "+hash);
  window.location.hash = hash;
});

function check_hash() {
  p("onhashchange");
  var hash = window.location.hash.substring(1);
  if (hash.length == 0) return;
  var json = JSON.parse(hash);
  //p(json);
  for (k in json) {
    if (Session.get(k) != json[k]) { 
      Session.set(k, json[k]);
    }
  }
}

window.onload = check_hash;

// TODO: fix this to not snapback
//window.onhashchange = check_hash;

Deps.autorun(function() {
  var cl_selector = $('#cl_selector');
  var clnum = Session.get("clnum");
  var max_clnum = Session.get("max_clnum");
  if (cl_selector.length > 0) {
    cl_selector[0].value = clnum;
    cl_selector[0].max = max_clnum;
    cl_selector.slider('refresh');
  }
});


Template.timeline.max_clnum = function() {
  post = Change.findOne({}, {sort: {clnum: -1}});
  if (post != undefined) {
    Session.setDefault("clnum", post.clnum);
    Session.set("max_clnum", post.clnum);
  }
};

Template.timeline.rendered = function() {
  $('#cl_selector').on("change", function(e) {
    var val = parseInt($('#cl_selector')[0].value);
    //p("change "+val);
    Session.set('clnum', val);
  });
};

Meteor.subscribe('max_clnum');

