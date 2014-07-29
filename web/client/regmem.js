stream = io.connect(STREAM_URL);

stream.on('maxclnum', function(msg) {
  update_maxclnum(msg);
});

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


stream.on('memory', function(msg) {
  // render the hex editor
  var addr = msg['address'];
  var PTRSIZE = msg['ptrsize'];
  html = "<table><tr>";
  for (var i = 0; i < msg['len']; i += PTRSIZE) {
    if ((i&0xF) == 0) html += "</tr><tr><td>"+hex(addr+i)+":</td>";
    html += "<td></td>";

    // check if it's an address
    var v = 0;

    if (msg['is_big_endian']) {
      for (var j = 0; j < PTRSIZE; j++) {
        if (addr+i+j == Session.get('daddr')) {
          exclass = "highlight";
        }
        v *= 0x100;
        var t = msg['dat'][addr+i+j];
        if (t !== undefined) v += t;
      }
    } else {
      for (var j = PTRSIZE-1; j >= 0; j--) {
        if (addr+i+j == Session.get('daddr')) {
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
      if (addr+i == Session.get('daddr')) { exclass = "highlight"; }
      html += '<td colspan="'+PTRSIZE+'" class="data '+a+' '+exclass+'" daddr='+(addr+i)+">"+me+"</td>";
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
        if (addr+i+j == Session.get('daddr')) { exclass = "highlight"; }
        html += '<td class="data '+exclass+'" daddr='+(addr+i+j)+">"+me+"</td>";
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
});



Template.regviewer.hexvalue = function() {
  return this.value;
};

Template.regviewer.datatype = function() {
  return get_data_type(this.value);
};

Template.regviewer.isselected = function() {
  if (Session.get('daddr') == this.address) {
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
  $('#regviewer')[0].innerHTML = "";
  var tsize = msg[0]['size'];
  if (tsize > 0) PTRSIZE = tsize;
  UI.insert(UI.renderWithData(Template.regviewer, {regs: msg}), $('#regviewer')[0]);

  // hack to display the change editor on x86 only
  if (msg[0]['name']=="EAX") $('#changeeditor').show();
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
  stream.emit('getclnum', forknum, Session.get('clnum'), ['L', 'S'], 2)
});

stream.on('clnum', function(msg) {
  $('#datachanges')[0].innerHTML = "";
  UI.insert(UI.renderWithData(Template.datachanges, {memactions: msg}), $('#datachanges')[0]);
});

