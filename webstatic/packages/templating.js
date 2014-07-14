//////////////////////////////////////////////////////////////////////////
//                                                                      //
// This is a generated file. You can view the original                  //
// source in your browser if your browser supports source maps.         //
//                                                                      //
// If you are using Chrome, open the Developer Tools and click the gear //
// icon in its lower right corner. In the General Settings panel, turn  //
// on 'Enable source maps'.                                             //
//                                                                      //
// If you are using Firefox 23, go to `about:config` and set the        //
// `devtools.debugger.source-maps-enabled` preference to true.          //
// (The preference should be on by default in Firefox 24; versions      //
// older than 23 do not support source maps.)                           //
//                                                                      //
//////////////////////////////////////////////////////////////////////////


(function () {

/* Imports */
var Meteor = Package.meteor.Meteor;
var UI = Package.ui.UI;
var Handlebars = Package.ui.Handlebars;
var HTML = Package.htmljs.HTML;

/* Package-scope variables */
var Template;

(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                    //
// packages/templating/global_template_object.js                                                                      //
//                                                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                      //
// Create an empty template object. Packages and apps add templates on                                                // 1
// to this object.                                                                                                    // 2
Template = {};                                                                                                        // 3
                                                                                                                      // 4
Template.__define__ = function (templateName, renderFunc) {                                                           // 5
  if (Template.hasOwnProperty(templateName))                                                                          // 6
    throw new Error("There are multiple templates named '" + templateName + "'. Each template needs a unique name."); // 7
                                                                                                                      // 8
  Template[templateName] = UI.Component.extend({                                                                      // 9
    kind: "Template_" + templateName,                                                                                 // 10
    render: renderFunc,                                                                                               // 11
    __helperHost: true                                                                                                // 12
  });                                                                                                                 // 13
};                                                                                                                    // 14
                                                                                                                      // 15
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);


/* Exports */
if (typeof Package === 'undefined') Package = {};
Package.templating = {
  Template: Template
};

})();

//# sourceMappingURL=b36d51fd34724d5d501d8557cd9f846874d95aef.map
