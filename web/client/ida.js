var ws = undefined;

function do_ida_socket(callme) {
  if (ws == undefined || ws.readyState == WebSocket.CLOSED) {
    ws = new WebSocket('ws://localhost:3003', 'qira');
    ws.onerror = function(e) {
      // TODO: why doesn't this catch the "net::ERR_CONNECTION_REFUSED"?
      // hmm, it looks like it does, but error is still printed to console
    };
    ws.onopen = function() {
      p('connected to IDA socket');
      callme();
    };
    ws.onmessage = function(msg) {
      //p(msg.data);
      var dat = msg.data.split(" ");
      if (dat[0] == "setiaddr") {
        Session.set("iaddr", dat[1]);
        Session.set("dirtyiaddr", true);
      }
      if (dat[0] == "setdaddr") {
        if (get_data_type(dat[1]) != "datainstruction") {
          update_dview(dat[1]);
        }
      }
    };
  } else {
    callme();
  }
}

Deps.autorun(function() { DA("send setaddress to ida");
  var iaddr = Session.get('iaddr');
  do_ida_socket(function() {
    cmd = 'setaddress '+iaddr;
    try {
      ws.send(cmd);
    } catch(err) {
      // nothing
    }
  });
});


