stream = new Meteor.Stream('regmem');

stream.on('memory', function(msg) {
  // render the hex editor
  var addr = msg['address'];
  html = "<table><tr>";
  str = "";
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
    var a = Pmaps.findOne({address: v - v%0x1000});
    if (a !== undefined) {
      var me = v.toString(16);
      //while (me.length != 8) me = "0" + me;
      me = "0x"+me;
      var exclass = "";
      if (addr+i == Session.get('daddr')) { exclass = "highlight"; }
      html += '<td colspan="4" class="data data'+a.type+' '+exclass+'" daddr='+(addr+i)+">"+me+"</td>";
    } else {
      for (var j = 0; j < 4; j++) {
        if (msg['dat'][addr+i+j] === undefined) {
          var me = "__";
          str += "&nbsp;";
        } else {
          var ii = msg['dat'][addr+i+j];
          if (ii >= 0x21 && ii <= 0x7e) str += String.fromCharCode(ii);
          else str += "&nbsp;";

          var me = ii.toString(16);
          if (me.length == 1) me = "0" + me;
        }
        var exclass = "";
        if (addr+i+j == Session.get('daddr')) { exclass = "highlight"; }
        html += '<td class="data '+exclass+'" daddr='+(addr+i+j)+">"+me+"</td>";
      }
    }

    if ((i&0xF) == 0xF) { html += "<td>" + str + "</td>"; str = ""; }
  }
  html += "</tr></table>";
  $("#hexdump")[0].innerHTML = html;
});

function update_dview(addr) {
  Session.set('daddr', addr);
  Session.set('dview', (addr-0x20)-(addr-0x20)%0x10);
}

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

stream.on('registers', function(msg) {
  $('#regviewer')[0].innerHTML = "";
  UI.insert(UI.renderWithData(Template.regviewer, {regs: msg}), $('#regviewer')[0]);
});

Template.regviewer.hexvalue = function() {
  return hex(this.value);
};

Template.regviewer.events({
  'click .daddress': function() {
    update_dview(this.value);
  },
});

// keep these updated
Deps.autorun(function() {
  var daddr = Session.get('daddr');
  var dview = Session.get('dview');
  var clnum = Session.get('clnum');
  stream.emit('getmemory', {"clnum":clnum, "address":dview, "len":0x100});
});

Deps.autorun(function() {
  stream.emit('getregisters', Session.get('clnum'));
});

Meteor.subscribe('pmaps');


