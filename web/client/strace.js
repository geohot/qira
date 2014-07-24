stream = io.connect(STREAM_URL);

stream.on('strace', function(msg) {
  //p(msg);
  $('#strace')[0].innerHTML = "";
  UI.insert(UI.renderWithData(Template.strace, {strace: msg}), $('#strace')[0]);
});

Template.strace.ischange = function() {
  var clnum = Session.get("clnum");
  if (this.clnum == clnum) return 'highlight';
  else return '';
}

Deps.autorun(function() {
  var forknum = Session.get("forknum");
  var maxclnum = Session.get("max_clnum");
  stream.emit("getstrace", forknum);
});

Template.strace.events({
  'click .change': function() {
    Session.set('clnum', this.clnum);
  },
});

