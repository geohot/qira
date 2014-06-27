stream = new Meteor.Stream('regmem');

stream.on('memory', function(msg) {
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

stream.on('registers', function(msg) {
  var newregs = [];
  for (i in msg) {
    newregs.push({"name":i, "value":msg[i]});
  }
  // hacks
  $('#regviewer')[0].innerHTML = "";
  UI.insert(UI.renderWithData(Template.regviewer, {regs: newregs}), $('#regviewer')[0]);
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
/*Deps.autorun(function() {
  var daddr = Session.get('daddr');
  var clnum = Session.get('clnum');
  do_socket(function() {
    socket.emit('getmemory',
      {"clnum":clnum-1, "address":(daddr-0x20)-(daddr-0x20)%0x10, "len":0x100});
  });
});*/

Deps.autorun(function() {
  stream.emit('getregisters', Session.get('clnum'));
});

