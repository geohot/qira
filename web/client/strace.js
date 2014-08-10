stream = io.connect(STREAM_URL);
Session.setDefault('sview', [0,10]);

traces = {}

stream.on('strace', function(msg) {
  traces[msg['forknum']] = msg['dat']
  redraw_strace();
});

function redraw_strace() {
  var forknum = Session.get("forknum");
  var sview = Session.get('sview');
  if (traces[forknum] === undefined) return;
  var msg = traces[forknum].slice(sview[0], sview[1])
  $('#strace')[0].innerHTML = "";
  UI.insert(UI.renderWithData(Template.strace, {strace: msg}), $('#strace')[0]);
}

Deps.autorun(function() {
  redraw_strace();
});


Template.strace.ischange = function() {
  var clnum = Session.get("clnum");
  if (this.clnum == clnum) return 'highlight';
  else return '';
}

// regetting strace whenever we change forks...perf hit
Deps.autorun(function() {
  var forknum = Session.get("forknum");
  var maxclnum = Session.get("max_clnum");
  stream.emit("getstrace", forknum);
});

Deps.autorun(function() {
  var forknum = Session.get("forknum");
  var clnum = Session.get("clnum");
  if (traces[forknum] === undefined) return;
  var t = traces[forknum];
  var i;
  for (i = 0; i < t.length; i++) {
    if (t[i]['clnum'] > clnum) break;
  }
  p(i);
  Session.set('sview', [i-3, i+7]);
});


Template.strace.events({
  'click .change': function() {
    Session.set('clnum', this.clnum);
  },
});

Template.strace.sc = function() { return highlight_addresses(this.sc); }

Meteor.startup(function() {
  $("#strace")[0].addEventListener("mousewheel", function(e) {
    var sv = Session.get('sview');
    if (e.wheelDelta < 0) {
      Session.set('sview', [sv[0]+1, sv[1]+1]);
    } else if (e.wheelDelta > 0) {
      if (sv[0] > 0) {
        Session.set('sview', [sv[0]-1, sv[1]-1]);
      }
    }
  });
});


