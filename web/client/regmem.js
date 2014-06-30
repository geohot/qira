stream = new Meteor.Stream('regmem');

stream.on('memory', function(msg) {
  // render the hex editor
  var addr = msg['address'];
  html = "<table><tr>";
  for (var i = 0; i < msg['len']; i++) {
    if ((i&0xF) == 0) html += "</tr><tr><td>"+hex(addr+i)+":</td>";
    if ((i&0x3) == 0) html += "<td></td>";
    if (msg['dat'][addr+i] === undefined) {
      var me = "&nbsp;&nbsp;";
    } else {
      var me = msg['dat'][addr+i].toString(16);
      if (me.length == 1) me = "0" + me;
    }
    if (addr+i == Session.get('daddr')) {
      html += '<td class="highlight">'+me+"</td>";
    } else {
      html += "<td>"+me+"</td>";
    }
  }
  html += "</tr></table>";
  $("#hexdump")[0].innerHTML = html;
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
    Session.set('daddr', this.value);
  },
});

// keep these updated
Deps.autorun(function() {
  var daddr = Session.get('daddr');
  var clnum = Session.get('clnum');
  stream.emit('getmemory',
      {"clnum":clnum-1, "address":(daddr-0x20)-(daddr-0x20)%0x10, "len":0x100});
});

Deps.autorun(function() {
  stream.emit('getregisters', Session.get('clnum'));
});

