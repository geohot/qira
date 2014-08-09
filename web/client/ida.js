var ws = undefined;

function do_ida_socket(callme) {
  if (ws == undefined || ws.readyState == WebSocket.CLOSED) {
    ws = new WebSocket('ws://localhost:3003', 'qira');
    ws.onopen = function() {
      p('connected to IDA socket');
      callme();
    };
    ws.onmessage = function(msg) {
      //p(msg.data);
      var dat = msg.data.split(" ");
      if (dat[0] == "setiaddr") {
        var addr = hex(parseInt(dat[1]));
        Session.set("iaddr", addr);
        Session.set("dirtyiaddr", true);
      }
      if (dat[0] == "setdaddr") {
        var addr = hex(parseInt(dat[1]));
        if (get_data_type(addr) != "datainstruction") {
          update_dview(addr);
        }
      }
    };
  } else {
    callme();
  }
}

Deps.autorun(function() {
  var iaddr = Session.get('iaddr');
  do_ida_socket(function() {
    cmd = 'setaddress '+fhex(iaddr)
    //p(cmd);
    ws.send(cmd);
  });
});


