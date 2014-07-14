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
var _ = Package.underscore._;

/* Package-scope variables */
var WebApp;

(function () {

///////////////////////////////////////////////////////////////////////
//                                                                   //
// packages/webapp/webapp_client.js                                  //
//                                                                   //
///////////////////////////////////////////////////////////////////////
                                                                     //
WebApp = {                                                           // 1
                                                                     // 2
  _isCssLoaded: function () {                                        // 3
    if (document.styleSheets.length === 0)                           // 4
      return true;                                                   // 5
                                                                     // 6
    return _.find(document.styleSheets, function (sheet) {           // 7
      if (sheet.cssText && !sheet.cssRules) // IE8                   // 8
        return !sheet.cssText.match(/meteor-css-not-found-error/);   // 9
      return !_.find(sheet.cssRules, function (rule) {               // 10
        return rule.selectorText === '.meteor-css-not-found-error';  // 11
      });                                                            // 12
    });                                                              // 13
  }                                                                  // 14
};                                                                   // 15
                                                                     // 16
///////////////////////////////////////////////////////////////////////

}).call(this);


/* Exports */
if (typeof Package === 'undefined') Package = {};
Package.webapp = {
  WebApp: WebApp
};

})();

//# sourceMappingURL=e1be090051b82f046484dccc2de7d747e50c7328.map
