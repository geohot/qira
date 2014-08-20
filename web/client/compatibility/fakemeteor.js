Deps = {
  _deps: {},
  autorun: function(fxn) {
    Session._track = [];
    fxn();
    var tracked = Session._track;
    Session._track = undefined;
    for (var i=0;i<tracked.length;i++) {
      if (Deps._deps[tracked[i]] === undefined) Deps._deps[tracked[i]] = [];
      Deps._deps[tracked[i]].push(fxn);
    }
  }
};

Session = {
  _pend: [],
  _pendTimeout: undefined,
  _process: function() {
    var _tpend = Session._pend;
    Session._pend = [];
    for (var i=0;i<_tpend.length;i++) {
      _tpend[i]();
    }
  },
  _track: undefined,
  _session: {},
  get: function(name) {
    if (Session._track !== undefined) Session._track.push(name);
    return Session._session[name];
  },
  set: function(name, data) {
    Session._session[name] = data;
    if (Deps._deps[name] !== undefined) {
      for (var i=0;i<Deps._deps[name].length;i++) {
        var fxn = Deps._deps[name][i];
        if (Session._pend.indexOf(fxn) == -1) Session._pend.push(fxn);
        window.clearTimeout(Session._pendTimeout);
        Session._pendTimeout = window.setTimeout(Session._process, 0);
      }
    }
  },
  setDefault: function(name, data) {
    if (Session.get(name) === undefined) {
      Session.set(name, data);
    }
  }
};

