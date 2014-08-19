(function(){
UI.body.contentParts.push(UI.Component.extend({render: (function() {
  var self = this;
  return HTML.Raw('<div id="vtimelinebox">\n</div>\n<div id="onlypanel">\n\n<div id="haddrline"></div>\n\n<div id="controls">\n<input spellcheck="false" id="control_clnum" class="control">\n<input spellcheck="false" id="control_forknum" class="control">\n<input spellcheck="false" id="control_iaddr" class="control">\n<input spellcheck="false" id="control_daddr" class="control">\n</div>\n\n<div>\n<div class="panelthing" id="idump">\n</div>\n</div>\n<div class="panelthing" id="regviewer">\n</div>\n<div class="panelthing" id="datachanges">\n</div>\n<div class="panelthing" id="hexeditor">\n<div id="hexdump"></div>\n</div>\n\n<div class="panelthing" id="strace">\n</div>\n</div>');
})}));
Meteor.startup(function () { if (! UI.body.INSTANTIATED) { UI.body.INSTANTIATED = true; UI.DomRange.insert(UI.render(UI.body).dom, document.body); } });

})();
