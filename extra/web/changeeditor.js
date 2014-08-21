Template.changeeditor.events = {
  'click #changeadd': function(e) {
    var pending = Session.get('pending');
    var daddr = Session.get('daddr');
    if (daddr === undefined) return;
    // no dups
    for (var i=0;i<pending.length;i++) {
      if (pending[i]['daddr'] == daddr) return;
    }
    pending[daddr] = "0x0";
    pending.push({"daddr": daddr, "ddata": "0x0"});
    Session.set('pending', pending);
  },
  'click #changeclear': function(e) {
    Session.set('pending', []);
  },
};

Deps.autorun(function() { DA("update pending changeeditor");
  var pending = Session.get('pending');
  if ($('#pending').length == 0) return;
  $('#pending')[0].innerHTML = "";
  UI.insert(UI.renderWithData(Template.pending, {pending: pending}), $('#pending')[0]);
});

Template.pending.events = {
  'change .changeedit': function(e) {
    var pending = Session.get('pending');
    for (var i=0;i<pending.length;i++) {
      if (pending[i]['daddr'] == this.daddr) {
        pending[i]['ddata'] = e.target.value;
        Session.set('pending', pending);
        return;
      }
    }
  },
};

