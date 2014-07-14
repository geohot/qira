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
var Deps = Package.deps.Deps;
var EJSON = Package.ejson.EJSON;

/* Package-scope variables */
var ReactiveDict;

(function () {

//////////////////////////////////////////////////////////////////////////////////////////
//                                                                                      //
// packages/reactive-dict/reactive-dict.js                                              //
//                                                                                      //
//////////////////////////////////////////////////////////////////////////////////////////
                                                                                        //
// XXX come up with a serialization method which canonicalizes object key               // 1
// order, which would allow us to use objects as values for equals.                     // 2
var stringify = function (value) {                                                      // 3
  if (value === undefined)                                                              // 4
    return 'undefined';                                                                 // 5
  return EJSON.stringify(value);                                                        // 6
};                                                                                      // 7
var parse = function (serialized) {                                                     // 8
  if (serialized === undefined || serialized === 'undefined')                           // 9
    return undefined;                                                                   // 10
  return EJSON.parse(serialized);                                                       // 11
};                                                                                      // 12
                                                                                        // 13
// migrationData, if present, should be data previously returned from                   // 14
// getMigrationData()                                                                   // 15
ReactiveDict = function (migrationData) {                                               // 16
  this.keys = migrationData || {}; // key -> value                                      // 17
  this.keyDeps = {}; // key -> Dependency                                               // 18
  this.keyValueDeps = {}; // key -> Dependency                                          // 19
};                                                                                      // 20
                                                                                        // 21
_.extend(ReactiveDict.prototype, {                                                      // 22
  set: function (key, value) {                                                          // 23
    var self = this;                                                                    // 24
                                                                                        // 25
    value = stringify(value);                                                           // 26
                                                                                        // 27
    var oldSerializedValue = 'undefined';                                               // 28
    if (_.has(self.keys, key)) oldSerializedValue = self.keys[key];                     // 29
    if (value === oldSerializedValue)                                                   // 30
      return;                                                                           // 31
    self.keys[key] = value;                                                             // 32
                                                                                        // 33
    var changed = function (v) {                                                        // 34
      v && v.changed();                                                                 // 35
    };                                                                                  // 36
                                                                                        // 37
    changed(self.keyDeps[key]);                                                         // 38
    if (self.keyValueDeps[key]) {                                                       // 39
      changed(self.keyValueDeps[key][oldSerializedValue]);                              // 40
      changed(self.keyValueDeps[key][value]);                                           // 41
    }                                                                                   // 42
  },                                                                                    // 43
                                                                                        // 44
  setDefault: function (key, value) {                                                   // 45
    var self = this;                                                                    // 46
    // for now, explicitly check for undefined, since there is no                       // 47
    // ReactiveDict.clear().  Later we might have a ReactiveDict.clear(), in which case // 48
    // we should check if it has the key.                                               // 49
    if (self.keys[key] === undefined) {                                                 // 50
      self.set(key, value);                                                             // 51
    }                                                                                   // 52
  },                                                                                    // 53
                                                                                        // 54
  get: function (key) {                                                                 // 55
    var self = this;                                                                    // 56
    self._ensureKey(key);                                                               // 57
    self.keyDeps[key].depend();                                                         // 58
    return parse(self.keys[key]);                                                       // 59
  },                                                                                    // 60
                                                                                        // 61
  equals: function (key, value) {                                                       // 62
    var self = this;                                                                    // 63
                                                                                        // 64
    // XXX hardcoded awareness of the 'mongo-livedata' package is not ideal             // 65
    var ObjectID = Package['mongo-livedata'] && Meteor.Collection.ObjectID;             // 66
                                                                                        // 67
    // We don't allow objects (or arrays that might include objects) for                // 68
    // .equals, because JSON.stringify doesn't canonicalize object key                  // 69
    // order. (We can make equals have the right return value by parsing the            // 70
    // current value and using EJSON.equals, but we won't have a canonical              // 71
    // element of keyValueDeps[key] to store the dependency.) You can still use         // 72
    // "EJSON.equals(reactiveDict.get(key), value)".                                    // 73
    //                                                                                  // 74
    // XXX we could allow arrays as long as we recursively check that there             // 75
    // are no objects                                                                   // 76
    if (typeof value !== 'string' &&                                                    // 77
        typeof value !== 'number' &&                                                    // 78
        typeof value !== 'boolean' &&                                                   // 79
        typeof value !== 'undefined' &&                                                 // 80
        !(value instanceof Date) &&                                                     // 81
        !(ObjectID && value instanceof ObjectID) &&                                     // 82
        value !== null)                                                                 // 83
      throw new Error("ReactiveDict.equals: value must be scalar");                     // 84
    var serializedValue = stringify(value);                                             // 85
                                                                                        // 86
    if (Deps.active) {                                                                  // 87
      self._ensureKey(key);                                                             // 88
                                                                                        // 89
      if (! _.has(self.keyValueDeps[key], serializedValue))                             // 90
        self.keyValueDeps[key][serializedValue] = new Deps.Dependency;                  // 91
                                                                                        // 92
      var isNew = self.keyValueDeps[key][serializedValue].depend();                     // 93
      if (isNew) {                                                                      // 94
        Deps.onInvalidate(function () {                                                 // 95
          // clean up [key][serializedValue] if it's now empty, so we don't             // 96
          // use O(n) memory for n = values seen ever                                   // 97
          if (! self.keyValueDeps[key][serializedValue].hasDependents())                // 98
            delete self.keyValueDeps[key][serializedValue];                             // 99
        });                                                                             // 100
      }                                                                                 // 101
    }                                                                                   // 102
                                                                                        // 103
    var oldValue = undefined;                                                           // 104
    if (_.has(self.keys, key)) oldValue = parse(self.keys[key]);                        // 105
    return EJSON.equals(oldValue, value);                                               // 106
  },                                                                                    // 107
                                                                                        // 108
  _ensureKey: function (key) {                                                          // 109
    var self = this;                                                                    // 110
    if (!(key in self.keyDeps)) {                                                       // 111
      self.keyDeps[key] = new Deps.Dependency;                                          // 112
      self.keyValueDeps[key] = {};                                                      // 113
    }                                                                                   // 114
  },                                                                                    // 115
                                                                                        // 116
  // Get a JSON value that can be passed to the constructor to                          // 117
  // create a new ReactiveDict with the same contents as this one                       // 118
  getMigrationData: function () {                                                       // 119
    // XXX sanitize and make sure it's JSONible?                                        // 120
    return this.keys;                                                                   // 121
  }                                                                                     // 122
});                                                                                     // 123
                                                                                        // 124
//////////////////////////////////////////////////////////////////////////////////////////

}).call(this);


/* Exports */
if (typeof Package === 'undefined') Package = {};
Package['reactive-dict'] = {
  ReactiveDict: ReactiveDict
};

})();

//# sourceMappingURL=22667928acc72f619ce81e7ac1e35def1ba9e0ae.map
