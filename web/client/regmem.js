stream = io.connect(STREAM_URL);

var regcolors = ['#59AE3F', '#723160', '#2A80A2', '#9E66BD', '#BC8D6B', '#3F3EAC', '#BC48B8', '#6B7C76', '#5FAC7F', '#A69B71', '#874535', '#AD49BF', '#73356F', '#55A4AC', '#988590', '#505C62', '#404088', '#56726B', '#BAAC62', '#454066', '#BCAEAA', '#4E7F6A', '#3960B5', '#295231', '#3B37A5', '#6A9191', '#976394', '#7F957D', '#B7AFBD', '#BD4A70', '#A35169', '#2F2D95', '#8879A8', '#8D3A8E', '#636E7C', '#82688D', '#9FA893', '#2A6885', '#812C87', '#568E71'];

var current_regs = undefined;

stream.on('maxclnum', function(msg) {
  update_maxclnum(msg);
});

stream.on('pmaps', function(msg) {
  Session.set('pmaps', msg)
});

function redraw_reg_flags() {
  $(".rflag").remove();
  if (current_regs !== undefined) {
    for (r in current_regs) {
      var th = current_regs[r];
      var t = $('#data_'+th.value);
      if (t.length == 1) {
        var rr = $('<div class="rflag"></div>');
        rr.css("background-color", regcolors[th.num]);
        var pos = t.children().length*3;  // rflag width
        rr.css("margin-left", pos+"px");
        t.prepend(rr);
      }
    }
  }
}

Meteor.startup(function() {
  $("#hexdump")[0].addEventListener("mousewheel", function(e) {
    if (e.wheelDelta < 0) {
      Session.set('dview', string_add(Session.get('dview'), 0x10));
    } else if (e.wheelDelta > 0) {
      Session.set('dview', string_add(Session.get('dview'), -0x10));
    }
  });
});


stream.on('memory', function(msg) {
  // render the hex editor
  // this isn't updated for numberless
  var addr = msg['address'];
  var daddr = fhex(Session.get('daddr'))
  var PTRSIZE = msg['ptrsize'];
  html = "<table><tr>";
  for (var i = 0; i < msg['len']; i += PTRSIZE) {
    if ((i&0xF) == 0) html += "</tr><tr><td>"+hex(addr+i)+":</td>";
    html += "<td></td>";

    // check if it's an address
    var v = 0;

    if (msg['is_big_endian']) {
      for (var j = 0; j < PTRSIZE; j++) {
        if (addr+i+j == daddr) {
          exclass = "highlight";
        }
        v *= 0x100;
        var t = msg['dat'][addr+i+j];
        if (t !== undefined) v += t;
      }
    } else {
      for (var j = PTRSIZE-1; j >= 0; j--) {
        if (addr+i+j == daddr) {
          exclass = "highlight";
        }
        v *= 0x100;
        var t = msg['dat'][addr+i+j];
        if (t !== undefined) v += t;
      }
    }
    var a = get_data_type(v);
    if (a !== "") {
      var me = v.toString(16);
      //while (me.length != 8) me = "0" + me;
      me = "0x"+me;
      var exclass = "";
      if (addr+i == daddr) { exclass = "highlight"; }
      html += '<td colspan="'+PTRSIZE+'" class="data '+a+' '+exclass+'" id=data_'+hex(addr+i)+">"+me+"</td>";
    } else {
      for (var j = 0; j < PTRSIZE; j++) {
        var ii = msg['dat'][addr+i+j];
        if (ii === undefined) {
          var me = "__";
        } else {
          var me = ii.toString(16);
          if (me.length == 1) me = "0" + me;
        }
        var exclass = "";
        if (addr+i+j == daddr) { exclass = "highlight"; }
        html += '<td class="data '+exclass+'" id=data_'+hex(addr+i+j)+">"+me+"</td>";
      }
    }

    // this must run on the last one too
    if ((i&0xF) == (0x10-PTRSIZE)) { 
      str = "";
      for (var j = 0; j < 0x10; j++) {
        // ewww
        var ii = msg['dat'][addr+i-(0x10-PTRSIZE)+j];
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
  redraw_reg_flags();
});


Template.regviewer.regcolor = function() {
  // draw the hflags here
  draw_hflag(this.value, this.name, regcolors[this.num]);
  return regcolors[this.num];
};

Template.regviewer.datatype = function() {
  return get_data_type(this.value);
};

Template.regviewer.isselected = function() {
  var daddr = fhex(Session.get('daddr'))
  if (daddr == this.address) {
    return 'highlight';
  } else {
    return '';
  }
};

// keep these updated
Deps.autorun(function() {
  var daddr = Session.get('daddr');
  var dview = Session.get('dview');
  var clnum = Session.get('clnum');
  var forknum = Session.get("forknum");
  stream.emit('getmemory', forknum, clnum-1, dview, 0x100);
});

Deps.autorun(function() {
  var forknum = Session.get("forknum");
  stream.emit('getregisters', forknum, Session.get('clnum')-1);
});

stream.on('registers', function(msg) {
  current_regs = msg;
  redraw_reg_flags();
  $('#regviewer')[0].innerHTML = "";
  var tsize = msg[0]['size'];
  if (tsize > 0) PTRSIZE = tsize;
  UI.insert(UI.renderWithData(Template.regviewer, {regs: msg}), $('#regviewer')[0]);
});

// events, add the editing here
Template.memviewer.events(basedblevents);
Template.regviewer.events(baseevents);
Template.datachanges.events(baseevents);

// *** datachanges ***

Template.datachanges.hexaddress = function() {
  return this.address;
};

Template.datachanges.typeclass = function() {
  if (this.type == "L") return "regread";
  else if (this.type == "S") return "regwrite";
};

Template.datachanges.hexdata = function() {
  return this.data;
};

Template.datachanges.addrtype = function() {
  return get_data_type(this.address);
};

Template.datachanges.datatype = function() {
  return get_data_type(this.data);
};

Deps.autorun(function() {
  var forknum = Session.get("forknum");
  stream.emit('getclnum', forknum, Session.get('clnum'), ['L', 'S'], 2)  // justification for more than 2?
});

stream.on('clnum', function(msg) {
  $('#datachanges')[0].innerHTML = "";
  UI.insert(UI.renderWithData(Template.datachanges, {memactions: msg}), $('#datachanges')[0]);
});

