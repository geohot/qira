Change = new Meteor.Collection("change");
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

if (Meteor.isClient) {
  window.onmousewheel = function(e) {
    if (e.wheelDelta < 0) {
      setters['clnum'](Session.get('clnum')+1);
    } else if (e.wheelDelta > 0) {
      setters['clnum'](Session.get('clnum')-1);
    }
  };

  var socket = undefined;
  function do_socket(callme) {
    if (socket == undefined || socket.socket.connected == false) {
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
        html = "";
        for (i in msg) {
          html += "<div class=reg>"+i+": "+hex(msg[i])+"</div>";
        }
        $("#regviewer")[0].innerHTML = html;
      });
    } else {
      callme();
    }
  }
  function update_hexeditor(daddr, clnum) {
    do_socket(function() {
      socket.emit('getmemory',
        {"clnum":clnum, "address":(daddr-0x20)-(daddr-0x20)%0x10, "len":0x100});
    });
  }

  function update_regdump(clnum) {
    do_socket(function() {
      socket.emit('getregisters', {"clnum":clnum});
    });
  }

  // there should be a library for this
  function update_hash() {
    var json = {};
    // must call session get to get a number
    for (k in Session.keys) { json[k] = Session.get(k); }
    var hash = JSON.stringify(json);
    //p("updating hash to "+hash);
    window.location.hash = hash;
  }
  var setters = {
    "maxclnum": function(clnum) {
      Session.set("maxclnum", clnum);
      Session.setDefault("clnum", clnum);
      if ($('#cl_selector').length > 0) {
        $('#cl_selector')[0].max = clnum;
        update_current_clnum(Session.get("clnum"));
      }
    },
    "clnum": function(clnum) {
      Session.set("clnum", clnum);
      update_hash();
      update_hexeditor(Session.get("daddr"), clnum);
      update_regdump(clnum);
    },
    "iaddr": function(iaddr) {
      Session.set("iaddr", iaddr);
      update_hash();
    },
    "daddr": function(daddr) {
      Session.set("daddr", daddr);
      update_hash();
      update_hexeditor(daddr, Session.get("clnum"));
    }
  };
  function check_hash() {
    var hash = window.location.hash.substring(1);
    if (hash.length == 0) return;
    var json = JSON.parse(hash);
    //p(json);
    for (k in json) {
      if (Session.get(k) != json[k]) { 
        setters[k](json[k]);
      }
    }
  }
  window.onload = check_hash;
  window.onhashchange = function() { check_hash(); }

  function update_current_clnum(clnum) {
    var cl_selector = $('#cl_selector');
    cl_selector[0].value = clnum;
    cl_selector.slider('refresh');
    $(".ui-slider-handle").select();
  }

  Template.cfg.isiaddr = function() {
    var iaddr = Session.get('iaddr');
    if (this.address == iaddr) return "highlight";
    else return "";
  }

  Template.cfg.hexaddress = function() { return hex(this.address)+": "; };

  Template.cfg.lineardump = function() {
    var iaddr = Session.get('iaddr');
    if (iaddr !== undefined) {
      return Program.find({address: {$gt: iaddr-0x30, $lt: iaddr+0x80}}, {sort: {address:1}});
    }
  };

  Template.timeline.max_clnum = function() {
    var post = Change.findOne({}, {sort: {clnum: -1}});
    if (post != undefined) {
      setters['maxclnum'](post.clnum);
    }
  };

  Template.timeline.rendered = function() {
    $('#cl_selector').on("change", function(e) {
      var val = parseInt($('#cl_selector')[0].value);
      setters['clnum'](val);
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
      update_current_clnum(this.clnum);
    }
  });
  Template.change.events({
    'click .address': function() {
      p("new daddr is "+hex(this.address));
      setters['daddr'](this.address);
    }
  });

  Template.cfg.events({
    'click .address': function() {
      p("new iaddr from click is "+hex(this.address));
      setters['iaddr'](this.address);
    }
  });

  Template.change.handleaddress = function () {
    if (this.type == "I") {
      p("new iaddr is "+hex(this.address));
      setters['iaddr'](this.address);
    }
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

  var subs = new Meteor.autosubscribe(function(){
    Meteor.subscribe('dat_iaddr', Session.get("iaddr"));
    Meteor.subscribe('dat_daddr', Session.get("daddr"));
    Meteor.subscribe('dat_clnum', Session.get("clnum"));

    Meteor.subscribe('hexedit_daddr', Session.get("daddr"), Session.get("clnum"));

    Meteor.subscribe('instruction_iaddr', Session.get("iaddr"));
  });
  Meteor.subscribe('max_clnum');
}

if (Meteor.isServer) {
  Meteor.startup(function () {
  });

  Meteor.publish('max_clnum', function() {
    // extract 'clnum' from this to get the max clnum
    return Change.find({}, {sort: {clnum: -1}, limit: 1});
  });

  Meteor.publish('dat_clnum', function(clnum){
    // can only return as many as in the changelist
    return Change.find({clnum: clnum}, {sort: {address: 1}, limit:20});
  });

  Meteor.publish('instruction_iaddr', function(iaddr){
    return Program.find({address: {$gt: iaddr-0x50, $lt: iaddr+0x100}}, {sort: {address:1}});
  });

  Meteor.publish('dat_iaddr', function(iaddr){
    // fetch the static info about the range
    return Change.find({address: iaddr, type: "I"}, {sort: {clnum: 1}, limit:10})
  });

  Meteor.publish('dat_daddr', function(daddr){
    // fetch the dynamic info about the instruction range
    //return Change.find({address : {$gt: daddr-0x100, $lt: daddr+0x300}});
    if (daddr >= 0x1000) {
      return Change.find({address:daddr}, {sort: {clnum: 1}, limit:10});
    } else {
      return false;
    }
  });

  Meteor.publish('hexedit_daddr', function(daddr, clnum) {
    return Change.find({address:daddr, clnum:{$lte: clnum}}, {sort: {clnum: -1}, limit:1});
  });
}


