stream = io.connect(STREAM_URL);
Session.setDefault('sview', [0,10]);

traces = {}

function on_strace(msg) { DS("strace");
  traces[msg['forknum']] = msg['dat']
  redraw_strace();
} stream.on('strace', on_strace);

function redraw_strace() {
  var forknum = Session.get("forknum");
  var sview = Session.get('sview');
  if (traces[forknum] === undefined) return;
  var msg = traces[forknum].slice(sview[0], sview[1])

  var strace = "";
  for (i in msg) {
    var st = msg[i];
    strace += '<div class="syscall">'+
        '<div class="change clnum clnum_'+st.clnum+'">'+st.clnum+'</div>'+
        highlight_addresses(st.sc)+
      '</div>';
  }
  $('#strace').html(strace);
  rehighlight();
}

Deps.autorun(function() { DA("redrawing strace");
  redraw_strace();
});

Deps.autorun(function() { DA("updating sview on fork/cl change");
  var forknum = Session.get("forknum");
  var clnum = Session.get("clnum");
  if (traces[forknum] === undefined) return;
  var t = traces[forknum];
  var i;
  // ugh, slow...binary search here
  for (i = 0; i < t.length; i++) {
    if (t[i]['clnum'] > clnum) break;
  }
  //p(i);
  var min = Math.max(0, i-3);
  var max = min+10;
  // ugh
  if (max > t.length) { 
    var off = max-t.length;
    max -= off; min -= off;
    if (min < 0) {
      max -= min;
      min = 0;
    }
  }
  Session.set('sview', [min, max]);
});

$(document).ready(function() {
  $("#strace")[0].addEventListener("mousewheel", function(e) {
    var sv = Session.get('sview');
    var forknum = Session.get("forknum");
    if (traces[forknum] === undefined) return;
    var t = traces[forknum];
    if (e.wheelDelta < 0) {
      if (sv[1] < t.length) {
        Session.set('sview', [sv[0]+1, sv[1]+1]);
      }
    } else if (e.wheelDelta > 0) {
      if (sv[0] > 0) {
        Session.set('sview', [sv[0]-1, sv[1]-1]);
      }
    }
  });
});


