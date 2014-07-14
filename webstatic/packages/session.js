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
var ReactiveDict = Package['reactive-dict'].ReactiveDict;
var EJSON = Package.ejson.EJSON;

/* Package-scope variables */
var Session;

(function () {

/////////////////////////////////////////////////////////////////////////
//                                                                     //
// packages/session/session.js                                         //
//                                                                     //
/////////////////////////////////////////////////////////////////////////
                                                                       //
var migratedKeys = {};                                                 // 1
if (Package.reload) {                                                  // 2
  var migrationData = Package.reload.Reload._migrationData('session'); // 3
  if (migrationData && migrationData.keys) {                           // 4
    migratedKeys = migrationData.keys;                                 // 5
  }                                                                    // 6
}                                                                      // 7
                                                                       // 8
Session = new ReactiveDict(migratedKeys);                              // 9
                                                                       // 10
if (Package.reload) {                                                  // 11
  Package.reload.Reload._onMigrate('session', function () {            // 12
    return [true, {keys: Session.keys}];                               // 13
  });                                                                  // 14
}                                                                      // 15
                                                                       // 16
/////////////////////////////////////////////////////////////////////////

}).call(this);


/* Exports */
if (typeof Package === 'undefined') Package = {};
Package.session = {
  Session: Session
};

})();

//# sourceMappingURL=5bcd2d86431dc10d5f4be0910cb6567342e1aaf6.map
