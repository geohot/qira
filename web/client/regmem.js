stream = new Meteor.Stream('regmem');

stream.on('memory', function(msg) {
  // render the hex editor
  var addr = msg['address'];
  html = "<table><tr>";
  str = "";
  for (var i = 0; i < msg['len']; i++) {
    if ((i&0xF) == 0) html += "</tr><tr><td>"+hex(addr+i)+":</td>";
    if ((i&0x3) == 0) html += "<td></td>";
    if (msg['dat'][addr+i] === undefined) {
      var me = "__";
      str += "&nbsp;";
    } else {
      var ii = msg['dat'][addr+i];
      if (ii >= 0x21 && ii <= 0x7e) str += String.fromCharCode(ii);
      else str += "&nbsp;";

      var me = ii.toString(16);
      if (me.length == 1) me = "0" + me;
    }
    if (addr+i == Session.get('daddr')) {
      html += '<td class="data highlight" daddr='+(addr+i)+'>'+me+"</td>";
    } else {
      html += '<td class="data" daddr='+(addr+i)+">"+me+"</td>";
    }
    if ((i&0xF) == 0xF) { html += "<td>" + str + "</td>"; str = ""; }
  }
  /*for (var i = 0; i < msg['len']; i+=4) {
    if ((i&0xF) == 0) html += "</tr><tr><td>"+hex(addr+i)+":</td>";

    var exclass = "";
    if (msg['dat'][addr+i] === undefined) {
      var me = "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
    } else {
      var v = 0;
      for (var j = 3; j >= 0; j--) {
        if (addr+i+j == Session.get('daddr')) {
          exclass = "highlight";
        }
        v *= 0x100;
        var t = msg['dat'][addr+i+j];
        if (t !== undefined) v += t;
      }
      var me = v.toString(16);
      while (me.length != 8) me = "0" + me;
    }
    html += '<td class="data '+exclass+'" daddr='+(addr+i)+">"+me+"</td>";
  }*/
  html += "</tr></table>";
  $("#hexdump")[0].innerHTML = html;
});

function update_dview(addr) {
  Session.set('daddr', addr);
  Session.set('dview', (addr-0x20)-(addr-0x20)%0x10);
}

Template.memviewer.events({
  'dblclick .data': function(e) {
    var daddr = parseInt(e.target.innerHTML, 16);
    update_dview(daddr);
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

