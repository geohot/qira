(function(){
UI.body.contentParts.push(UI.Component.extend({render: (function() {
  var self = this;
  return [ HTML.Raw('<div id="vtimelinebox">\n<!--<div class="vtimeline" id="vtimeline0"></div>\n<div class="vtimeline" id="vtimeline1"></div>-->\n<div id="trash">delete</div>\n</div>\n'), HTML.DIV({
    id: "onlypanel"
  }, "\n", HTML.DIV({
    id: "controls"
  }, "\n", Spacebars.include(self.lookupTemplate("controls")), "\n"), "\n\n", HTML.DIV("\n\n", HTML.DIV({
    "class": "panelthing",
    id: "changeeditor"
  }, "\n", Spacebars.include(self.lookupTemplate("changeeditor")), "\n"), "\n\n", HTML.DIV({
    "class": "panelthing",
    id: "idump"
  }, "\n", Spacebars.include(self.lookupTemplate("idump")), "\n"), "\n"), HTML.Raw('\n\n<div class="panelthing" id="regviewer">\n</div>\n'), HTML.DIV({
    "class": "panelthing",
    id: "datachanges"
  }, "\n", Spacebars.include(self.lookupTemplate("datachanges")), "\n"), "\n", HTML.DIV({
    "class": "panelthing",
    id: "hexeditor"
  }, "\n", Spacebars.include(self.lookupTemplate("memviewer")), "\n"), "\n", HTML.DIV({
    "class": "panelthing",
    id: "strace"
  }, "\n", Spacebars.include(self.lookupTemplate("strace")), "\n"), "\n") ];
})}));
Meteor.startup(function () { if (! UI.body.INSTANTIATED) { UI.body.INSTANTIATED = true; UI.DomRange.insert(UI.render(UI.body).dom, document.body); } });

Template.__define__("controls", (function() {
  var self = this;
  var template = this;
  return [ HTML.INPUT({
    spellcheck: "false",
    id: "control_clnum",
    "class": "control datachange",
    value: function() {
      return Spacebars.mustache(self.lookup("clnum"));
    }
  }), "\n", HTML.INPUT({
    spellcheck: "false",
    id: "control_forknum",
    "class": "control",
    value: function() {
      return Spacebars.mustache(self.lookup("forknum"));
    }
  }), HTML.Raw('\n<input type="button" value="fork" id="control_fork" class="control">\n'), HTML.INPUT({
    spellcheck: "false",
    id: "control_iaddr",
    "class": "control datainstruction",
    value: function() {
      return Spacebars.mustache(self.lookup("iaddr"));
    }
  }), "\n", HTML.INPUT({
    spellcheck: "false",
    id: "control_daddr",
    "class": "control datamemory",
    value: function() {
      return Spacebars.mustache(self.lookup("daddr"));
    }
  }) ];
}));

Template.__define__("strace", (function() {
  var self = this;
  var template = this;
  return UI.Each(function() {
    return Spacebars.call(self.lookup("strace"));
  }, UI.block(function() {
    var self = this;
    return [ "\n  ", HTML.DIV({
      "class": "syscall"
    }, "\n  ", HTML.DIV({
      "class": [ "change ", function() {
        return Spacebars.mustache(self.lookup("ischange"));
      } ]
    }, function() {
      return Spacebars.mustache(self.lookup("clnum"));
    }), "\n  ", function() {
      return Spacebars.mustache(self.lookup("sc"));
    }, "\n  "), "\n" ];
  }));
}));

Template.__define__("changeeditor", (function() {
  var self = this;
  var template = this;
  return [ HTML.Raw('<input id="changeadd" type="button" value="Add Change">\n<input id="changeclear" type="button" value="Clear">\n'), HTML.DIV({
    id: "pending"
  }, "\n", Spacebars.include(self.lookupTemplate("pending")), "\n") ];
}));

Template.__define__("pending", (function() {
  var self = this;
  var template = this;
  return HTML.TABLE("\n", UI.Each(function() {
    return Spacebars.call(self.lookup("pending"));
  }, UI.block(function() {
    var self = this;
    return [ "\n", HTML.TR("\n", HTML.TD(function() {
      return Spacebars.mustache(self.lookup("daddr"));
    }), HTML.TD("="), "\n", HTML.INPUT({
      spellcheck: "false",
      "class": "changeedit",
      value: function() {
        return Spacebars.mustache(self.lookup("ddata"));
      }
    }), "\n"), "\n" ];
  })), "\n");
}));

Template.__define__("idump", (function() {
  var self = this;
  var template = this;
  return UI.Each(function() {
    return Spacebars.call(self.lookup("instructions"));
  }, UI.block(function() {
    var self = this;
    return [ "\n  ", HTML.DIV({
      "class": "instruction"
    }, "\n  ", HTML.DIV({
      "class": [ "change ", function() {
        return Spacebars.mustache(self.lookup("ischange"));
      } ]
    }, function() {
      return Spacebars.mustache(self.lookup("clnum"));
    }), "\n  ", HTML.SPAN({
      "class": [ "datainstruction ", function() {
        return Spacebars.mustache(self.lookup("isiaddr"));
      } ]
    }, function() {
      return Spacebars.mustache(self.lookup("hexaddress"));
    }), "\n  ", function() {
      return Spacebars.mustache(self.lookup("instruction"));
    }, "\n  "), "\n" ];
  }));
}));

Template.__define__("regviewer", (function() {
  var self = this;
  var template = this;
  return UI.Each(function() {
    return Spacebars.call(self.lookup("regs"));
  }, UI.block(function() {
    var self = this;
    return [ "\n  ", HTML.DIV({
      "class": [ "reg ", function() {
        return Spacebars.mustache(self.lookup("regactions"));
      } ]
    }, "\n  ", HTML.SPAN({
      "class": "register"
    }, function() {
      return Spacebars.mustache(self.lookup("name"));
    }, ": "), HTML.SPAN({
      "class": [ function() {
        return Spacebars.mustache(self.lookup("datatype"));
      }, " ", function() {
        return Spacebars.mustache(self.lookup("isselected"));
      } ]
    }, function() {
      return Spacebars.mustache(self.lookup("hexvalue"));
    }), "\n  "), "\n" ];
  }));
}));

Template.__define__("datachanges", (function() {
  var self = this;
  var template = this;
  return UI.Each(function() {
    return Spacebars.call(self.lookup("memactions"));
  }, UI.block(function() {
    var self = this;
    return [ "\n    ", HTML.DIV({
      "class": [ "datachanges ", function() {
        return Spacebars.mustache(self.lookup("typeclass"));
      } ]
    }, "\n      ", HTML.SPAN({
      "class": function() {
        return Spacebars.mustache(self.lookup("addrtype"));
      }
    }, function() {
      return Spacebars.mustache(self.lookup("hexaddress"));
    }), "\n      ", HTML.CharRef({
      html: "&lt;",
      str: "<"
    }), "--\n      ", HTML.SPAN({
      "class": function() {
        return Spacebars.mustache(self.lookup("datatype"));
      }
    }, function() {
      return Spacebars.mustache(self.lookup("hexdata"));
    }), "\n    "), "\n  " ];
  }));
}));

Template.__define__("memviewer", (function() {
  var self = this;
  var template = this;
  return HTML.Raw('<div id="hexdump"></div>');
}));

})();
