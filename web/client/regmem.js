stream = io.connect("http://localhost:3002/qira");

stream.on('maxclnum', function(msg) {
  update_maxclnum(msg);
});

pmaps = {}
stream.on('pmaps', function(msg) {
  pmaps = msg
});

Meteor.startup(function() {
  $("#hexdump")[0].addEventListener("mousewheel", function(e) {
    if (e.wheelDelta < 0) {
      Session.set('dview', Session.get('dview')+0x10);
    } else if (e.wheelDelta > 0) {
      Session.set('dview', Session.get('dview')-0x10);
    }
  });
});

function get_data_type(v) {
  var a = pmaps[v - v%0x1000];
  if (a === undefined) return "";
  else return "data"+a;
}

stream.on('memory', function(msg) {
  // render the hex editor
  var addr = msg['address'];
  html = "<table><tr>";
  for (var i = 0; i < msg['len']; i+=4) {
    if ((i&0xF) == 0) html += "</tr><tr><td>"+hex(addr+i)+":</td>";
    html += "<td></td>";

    // check if it's an address
    var v = 0;
    
    for (var j = 3; j >= 0; j--) {
      if (addr+i+j == Session.get('daddr')) {
        exclass = "highlight";
      }
      v *= 0x100;
      var t = msg['dat'][addr+i+j];
      if (t !== undefined) v += t;
    }
    var a = get_data_type(v);
    if (a !== "") {
      var me = v.toString(16);
      //while (me.length != 8) me = "0" + me;
      me = "0x"+me;
      var exclass = "";
      if (addr+i == Session.get('daddr')) { exclass = "highlight"; }
      html += '<td colspan="4" class="data '+a+' '+exclass+'" daddr='+(addr+i)+">"+me+"</td>";
    } else {
      for (var j = 0; j < 4; j++) {
        var ii = msg['dat'][addr+i+j];
        if (ii === undefined) {
          var me = "__";
        } else {
          var me = ii.toString(16);
          if (me.length == 1) me = "0" + me;
        }
        var exclass = "";
        if (addr+i+j == Session.get('daddr')) { exclass = "highlight"; }
        html += '<td class="data '+exclass+'" daddr='+(addr+i+j)+">"+me+"</td>";
      }
    }

    // this must run on the last one too
    if ((i&0xF) == 0xC) { 
      str = "";
      for (var j = 0; j < 0x10; j++) {
        // ewww
        var ii = msg['dat'][addr+i-0xC+j];
        if (ii == 0x20) str += "&nbsp;";
        else if (ii == 0x26) str += "&amp;";
        else if (ii == 0x3C) str += "&lt;";
        else if (ii == 0x3E) str += "&gt;";
        else if (ii >= 0x21 && ii <= 0x7e) str += String.fromCharCode(ii);
        else if (ii == undefined) str += "&nbsp;";
        else str += ".";
      }
      html += "<td>" + str + "</td>"; str = "";
    }
  }
  html += "</tr></table>";
  $("#hexdump")[0].innerHTML = html;
});


Template.memviewer.events({
  'dblclick .datamemory': function(e) {
    var daddr = parseInt(e.target.innerHTML, 16);
    update_dview(daddr);
  },
  'dblclick .datainstruction': function(e) {
    var iaddr = parseInt(e.target.innerHTML, 16);
    Session.set('iaddr', iaddr);
  },
  'click .data': function(e) {
    var daddr = parseInt(e.target.getAttribute('daddr'));
    Session.set('daddr', daddr);
  },
});

Template.regviewer.events(baseevents);

Template.regviewer.hexvalue = function() {
  return hex(this.value);
};

Template.regviewer.datatype = function() {
  return get_data_type(this.value);
};

// keep these updated
Deps.autorun(function() {
  var daddr = Session.get('daddr');
  var dview = Session.get('dview');
  var clnum = Session.get('clnum');
  stream.emit('getmemory', {"clnum":clnum-1, "address":dview, "len":0x100});
});

Deps.autorun(function() {
  stream.emit('getregisters', Session.get('clnum')-1);
});

stream.on('registers', function(msg) {
  $('#regviewer')[0].innerHTML = "";
  UI.insert(UI.renderWithData(Template.regviewer, {regs: msg}), $('#regviewer')[0]);
});

// *** datachanges ***

Template.datachanges.events(baseevents);

Template.datachanges.hexaddress = function() {
  return hex(this.address);
};

Template.datachanges.typeclass = function() {
  if (this.type == "L") return "regread";
  else if (this.type == "S") return "regwrite";
};

Template.datachanges.hexdata = function() {
  return hex(this.data);
};

Template.datachanges.addrtype = function() {
  return get_data_type(this.address);
};

Template.datachanges.datatype = function() {
  return get_data_type(this.data);
};

Deps.autorun(function() {
  stream.emit('getclnum', {'clnum': Session.get('clnum'), 'types': ['L', 'S'], 'limit': 3});
});

stream.on('clnum', function(msg) {
  $('#datachanges')[0].innerHTML = "";
  UI.insert(UI.renderWithData(Template.datachanges, {memactions: msg}), $('#datachanges')[0]);
});



