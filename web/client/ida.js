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
      var dat = msg.data.split(" ");
      if (dat[0] == "setiaddr") {
        Session.set("iaddr", dat[1]);
        Session.set("dirtyiaddr", true);
      }
      else if (dat[0] == "setdaddr") {
        if (get_data_type(dat[1]) != "datainstruction") {
          update_dview(dat[1]);
        }
      }
      else if (dat[0] == "setname") {
        var send = {}
        var address = dat[1];
        var name = dat[2];
        send[address] = {"name": name};
        stream.emit("settags", send);
      }
      else if (dat[0] == "setcmt") {
        var send = {}
        var address = dat[1];
        var comment = dat.slice(2).join(" ");
        send[address] = {"comment": comment};
        stream.emit("settags", send);
      }
    };
  } else {
    callme();
  }
}

function send_cmd(cmd) {
  do_ida_socket(function() {
    try {
      ws.send(cmd);
    } catch(err) {
      // nothing
    }
  });
}

Deps.autorun(function() { DA("send setaddress to ida");
  var iaddr = Session.get('iaddr');
  send_cmd('setaddress '+iaddr);
});

Deps.autorun(function() { DA("send user names and comments to ida");
  var addr = Session.get("ida_sync_addr");
  var tagname = Session.get("ida_sync_tagname");
  var dat = Session.get("ida_sync_dat");

  if (addr == undefined || tagname == undefined || dat == undefined) return;

  if (tagname == "name")
    send_cmd('setname ' + addr + " " + dat);
  else if (tagname == "comment")
    send_cmd('setcmt ' + addr + " " + dat);
  else {
    p("Unknown tag type from IDA plugin: " + tagname)
  }
});

Deps.autorun(function() { DA("send trail to ida");
  var trail = Session.get("trail");
  if (trail !== undefined) {
    var s = "settrail ";
    for (var i = 0; i < trail.length; i++) {
      var cldiff = trail[i][0];
      var addr = trail[i][1];
      if (-10 <= cldiff && cldiff <= 0) {
        s += cldiff + "," + addr + ";";
      }
    }
    p(s);
    send_cmd(s);
  }
});
