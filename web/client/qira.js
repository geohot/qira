Change = new Meteor.Collection("change");
Blocks = new Meteor.Collection("blocks");
Program = new Meteor.Collection("program");

// bitops make numbers negative

var X86REGS = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI', 'EIP'];

function p(a) {
  console.log(a);
}

function hex(a) {
  if (a == undefined) {
    return "";
  } else {
    if (a < 0) a += 0x100000000;
    return "0x"+a.toString(16);
  }
}

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
      p(msg);
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

Template.cfg.isiaddr = function() {
  var iaddr = Session.get('iaddr');
  if (this.address == iaddr) return "highlight";
  else return "";
}
Template.cfg.ischange = function() {
  var clnum = Session.get('clnum');
  if (this.clnum == clnum) return "highlight";
  else return "";
}

Template.cfg.hexaddress = function() { return hex(this.address)+": "; };
Template.cfg.hexstart = function() { return hex(this.start); };
Template.cfg.hexend = function() { return hex(this.end); };

Template.cfg.instruction = function() {
  te = Program.findOne({address: this.address});
  if (te !== undefined) {
    return te.instruction;
  }
};

Template.cfg.instructions = function() {
  //p(this.clstart + " " + this.clend);
  var changes = Change.find({clnum: {$gte: this.clstart, $lte: this.clend}, type: "I"}, {sort: {clnum: 1}});
  var query = [];
  /*changes.forEach(function(post) {
    //p(post);
    query.push({address: post.address});
  });*/
  //var progdat = Program.find({$or: query}, {sort: {address: 1}});
  //return progdat;
  return changes;
}

Template.cfg.blocks = function() {
  var clnum = Session.get('clnum');
  var BEFORE = clnum-0x10;
  var AFTER = clnum+0x28;
  var cblocks = Blocks.find({clend: {$gt: BEFORE}, clstart: {$lt: AFTER}}, {sort: {clstart: 1}});
  return cblocks;
};

Template.cfg.lineardump = function() {
  //var iaddr = Session.get('iaddr');
  var clnum = Session.get('clnum');
  if (clnum !== undefined) {
    return Change.find({clnum: {$gt: clnum-0x10, $lt: clnum+0x18}, type: "I"}, {sort: {clnum:1}});
  }
};

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

Template.changelist.currentchanges = function() {
  var clnum = Session.get('clnum');
  return Change.find({clnum: clnum}, {sort: {address: 1}, limit:20});
};

Template.changelist.iaddr = function() { return hex(Session.get('iaddr')); };
Template.changelist.daddr = function() { return hex(Session.get('daddr')); };
Template.changelist.clnum = function() { return Session.get('clnum'); };

Template.changelist.icllist = function() {
  var iaddr = Session.get('iaddr');
  return Change.find({address: iaddr, type: "I"}, {sort: {clnum: 1},limit:10})
};

Template.changelist.dcllist = function() {
  var daddr = Session.get('daddr');
  if (daddr >= 0x1000) {
    return Change.find({address:daddr}, {sort: {clnum: 1},limit:10});
  } else {
    return false;
  }
};

Template.change.is_mem = function() {
  return this.type == "L" || this.type == "S";
};

Template.cl.events({
  'click .change': function() {
    Session.set('clnum', this.clnum);
  }
});

Template.changelist.events({
  'change #daddr_input': function() {
    if ($("#daddr_input")[0].value == "") {
      Session.set('daddr', undefined);
      return;
    }
    var daddr = parseInt($("#daddr_input")[0].value, 16);
    p("new daddr is "+daddr);
    Session.set('daddr', daddr);
  }
});

Template.change.events({
  'click .address': function() {
    p("new daddr is "+hex(this.address));
    Session.set('daddr', this.address);
  }
});

Template.cfg.events({
  'click .address': function() {
    p("new iaddr from click is "+hex(this.address));
    Session.set('iaddr', this.address);
  },
  'click .change': function() {
    Session.set('clnum', this.clnum);
  }
});

Template.change.handleaddress = function () {
  /*if (this.type == "I") {
    p("new iaddr is "+hex(this.address));
    Session.set('iaddr', this.address);
  }*/
  if (this.type == "R" || this.type == "W") {
    if (this.address < (X86REGS.length*4)) {
      return X86REGS[this.address/4];
    } else {
      return hex(this.address);
    }
  } else {
    return hex(this.address);
  }
};

Template.change.handledata = function () {
  return hex(this.data);
};

Deps.autorun(function(){ Meteor.subscribe('dat_iaddr', Session.get("iaddr")); });
Deps.autorun(function(){ Meteor.subscribe('dat_daddr', Session.get("daddr")); });
/*Deps.autorun(function(){ Meteor.subscribe('dat_clnum', Session.get("clnum")); });
Deps.autorun(function(){ Meteor.subscribe('hexedit_daddr', Session.get("daddr"), Session.get("clnum")); });
Deps.autorun(function(){ Meteor.subscribe('instruction_iaddr', Session.get("iaddr")); });*/

Deps.autorun(function(){ Meteor.subscribe('dat_clnum', Session.get("clnum")); });
Deps.autorun(function(){ Meteor.subscribe('instructions', Session.get("clnum")); });

Meteor.subscribe('max_clnum');

