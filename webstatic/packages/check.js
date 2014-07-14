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
var EJSON = Package.ejson.EJSON;

/* Package-scope variables */
var check, Match;

(function () {

///////////////////////////////////////////////////////////////////////////////////
//                                                                               //
// packages/check/match.js                                                       //
//                                                                               //
///////////////////////////////////////////////////////////////////////////////////
                                                                                 //
// XXX docs                                                                      // 1
                                                                                 // 2
// Things we explicitly do NOT support:                                          // 3
//    - heterogenous arrays                                                      // 4
                                                                                 // 5
var currentArgumentChecker = new Meteor.EnvironmentVariable;                     // 6
                                                                                 // 7
check = function (value, pattern) {                                              // 8
  // Record that check got called, if somebody cared.                            // 9
  //                                                                             // 10
  // We use getOrNullIfOutsideFiber so that it's OK to call check()              // 11
  // from non-Fiber server contexts; the downside is that if you forget to       // 12
  // bindEnvironment on some random callback in your method/publisher,           // 13
  // it might not find the argumentChecker and you'll get an error about         // 14
  // not checking an argument that it looks like you're checking (instead        // 15
  // of just getting a "Node code must run in a Fiber" error).                   // 16
  var argChecker = currentArgumentChecker.getOrNullIfOutsideFiber();             // 17
  if (argChecker)                                                                // 18
    argChecker.checking(value);                                                  // 19
  try {                                                                          // 20
    checkSubtree(value, pattern);                                                // 21
  } catch (err) {                                                                // 22
    if ((err instanceof Match.Error) && err.path)                                // 23
      err.message += " in field " + err.path;                                    // 24
    throw err;                                                                   // 25
  }                                                                              // 26
};                                                                               // 27
                                                                                 // 28
Match = {                                                                        // 29
  Optional: function (pattern) {                                                 // 30
    return new Optional(pattern);                                                // 31
  },                                                                             // 32
  OneOf: function (/*arguments*/) {                                              // 33
    return new OneOf(_.toArray(arguments));                                      // 34
  },                                                                             // 35
  Any: ['__any__'],                                                              // 36
  Where: function (condition) {                                                  // 37
    return new Where(condition);                                                 // 38
  },                                                                             // 39
  ObjectIncluding: function (pattern) {                                          // 40
    return new ObjectIncluding(pattern);                                         // 41
  },                                                                             // 42
  // Matches only signed 32-bit integers                                         // 43
  Integer: ['__integer__'],                                                      // 44
                                                                                 // 45
  // XXX matchers should know how to describe themselves for errors              // 46
  Error: Meteor.makeErrorType("Match.Error", function (msg) {                    // 47
    this.message = "Match error: " + msg;                                        // 48
    // The path of the value that failed to match. Initially empty, this gets    // 49
    // populated by catching and rethrowing the exception as it goes back up the // 50
    // stack.                                                                    // 51
    // E.g.: "vals[3].entity.created"                                            // 52
    this.path = "";                                                              // 53
    // If this gets sent over DDP, don't give full internal details but at least // 54
    // provide something better than 500 Internal server error.                  // 55
    this.sanitizedError = new Meteor.Error(400, "Match failed");                 // 56
  }),                                                                            // 57
                                                                                 // 58
  // Tests to see if value matches pattern. Unlike check, it merely returns true // 59
  // or false (unless an error other than Match.Error was thrown). It does not   // 60
  // interact with _failIfArgumentsAreNotAllChecked.                             // 61
  // XXX maybe also implement a Match.match which returns more information about // 62
  //     failures but without using exception handling or doing what check()     // 63
  //     does with _failIfArgumentsAreNotAllChecked and Meteor.Error conversion  // 64
  test: function (value, pattern) {                                              // 65
    try {                                                                        // 66
      checkSubtree(value, pattern);                                              // 67
      return true;                                                               // 68
    } catch (e) {                                                                // 69
      if (e instanceof Match.Error)                                              // 70
        return false;                                                            // 71
      // Rethrow other errors.                                                   // 72
      throw e;                                                                   // 73
    }                                                                            // 74
  },                                                                             // 75
                                                                                 // 76
  // Runs `f.apply(context, args)`. If check() is not called on every element of // 77
  // `args` (either directly or in the first level of an array), throws an error // 78
  // (using `description` in the message).                                       // 79
  //                                                                             // 80
  _failIfArgumentsAreNotAllChecked: function (f, context, args, description) {   // 81
    var argChecker = new ArgumentChecker(args, description);                     // 82
    var result = currentArgumentChecker.withValue(argChecker, function () {      // 83
      return f.apply(context, args);                                             // 84
    });                                                                          // 85
    // If f didn't itself throw, make sure it checked all of its arguments.      // 86
    argChecker.throwUnlessAllArgumentsHaveBeenChecked();                         // 87
    return result;                                                               // 88
  }                                                                              // 89
};                                                                               // 90
                                                                                 // 91
var Optional = function (pattern) {                                              // 92
  this.pattern = pattern;                                                        // 93
};                                                                               // 94
                                                                                 // 95
var OneOf = function (choices) {                                                 // 96
  if (_.isEmpty(choices))                                                        // 97
    throw new Error("Must provide at least one choice to Match.OneOf");          // 98
  this.choices = choices;                                                        // 99
};                                                                               // 100
                                                                                 // 101
var Where = function (condition) {                                               // 102
  this.condition = condition;                                                    // 103
};                                                                               // 104
                                                                                 // 105
var ObjectIncluding = function (pattern) {                                       // 106
  this.pattern = pattern;                                                        // 107
};                                                                               // 108
                                                                                 // 109
var typeofChecks = [                                                             // 110
  [String, "string"],                                                            // 111
  [Number, "number"],                                                            // 112
  [Boolean, "boolean"],                                                          // 113
  // While we don't allow undefined in EJSON, this is good for optional          // 114
  // arguments with OneOf.                                                       // 115
  [undefined, "undefined"]                                                       // 116
];                                                                               // 117
                                                                                 // 118
var checkSubtree = function (value, pattern) {                                   // 119
  // Match anything!                                                             // 120
  if (pattern === Match.Any)                                                     // 121
    return;                                                                      // 122
                                                                                 // 123
  // Basic atomic types.                                                         // 124
  // Do not match boxed objects (e.g. String, Boolean)                           // 125
  for (var i = 0; i < typeofChecks.length; ++i) {                                // 126
    if (pattern === typeofChecks[i][0]) {                                        // 127
      if (typeof value === typeofChecks[i][1])                                   // 128
        return;                                                                  // 129
      throw new Match.Error("Expected " + typeofChecks[i][1] + ", got " +        // 130
                            typeof value);                                       // 131
    }                                                                            // 132
  }                                                                              // 133
  if (pattern === null) {                                                        // 134
    if (value === null)                                                          // 135
      return;                                                                    // 136
    throw new Match.Error("Expected null, got " + EJSON.stringify(value));       // 137
  }                                                                              // 138
                                                                                 // 139
  // Match.Integer is special type encoded with array                            // 140
  if (pattern === Match.Integer) {                                               // 141
    // There is no consistent and reliable way to check if variable is a 64-bit  // 142
    // integer. One of the popular solutions is to get reminder of division by 1 // 143
    // but this method fails on really large floats with big precision.          // 144
    // E.g.: 1.348192308491824e+23 % 1 === 0 in V8                               // 145
    // Bitwise operators work consistantly but always cast variable to 32-bit    // 146
    // signed integer according to JavaScript specs.                             // 147
    if (typeof value === "number" && (value | 0) === value)                      // 148
      return                                                                     // 149
    throw new Match.Error("Expected Integer, got "                               // 150
                + (value instanceof Object ? EJSON.stringify(value) : value));   // 151
  }                                                                              // 152
                                                                                 // 153
  // "Object" is shorthand for Match.ObjectIncluding({});                        // 154
  if (pattern === Object)                                                        // 155
    pattern = Match.ObjectIncluding({});                                         // 156
                                                                                 // 157
  // Array (checked AFTER Any, which is implemented as an Array).                // 158
  if (pattern instanceof Array) {                                                // 159
    if (pattern.length !== 1)                                                    // 160
      throw Error("Bad pattern: arrays must have one type element" +             // 161
                  EJSON.stringify(pattern));                                     // 162
    if (!_.isArray(value) && !_.isArguments(value)) {                            // 163
      throw new Match.Error("Expected array, got " + EJSON.stringify(value));    // 164
    }                                                                            // 165
                                                                                 // 166
    _.each(value, function (valueElement, index) {                               // 167
      try {                                                                      // 168
        checkSubtree(valueElement, pattern[0]);                                  // 169
      } catch (err) {                                                            // 170
        if (err instanceof Match.Error) {                                        // 171
          err.path = _prependPath(index, err.path);                              // 172
        }                                                                        // 173
        throw err;                                                               // 174
      }                                                                          // 175
    });                                                                          // 176
    return;                                                                      // 177
  }                                                                              // 178
                                                                                 // 179
  // Arbitrary validation checks. The condition can return false or throw a      // 180
  // Match.Error (ie, it can internally use check()) to fail.                    // 181
  if (pattern instanceof Where) {                                                // 182
    if (pattern.condition(value))                                                // 183
      return;                                                                    // 184
    // XXX this error is terrible                                                // 185
    throw new Match.Error("Failed Match.Where validation");                      // 186
  }                                                                              // 187
                                                                                 // 188
                                                                                 // 189
  if (pattern instanceof Optional)                                               // 190
    pattern = Match.OneOf(undefined, pattern.pattern);                           // 191
                                                                                 // 192
  if (pattern instanceof OneOf) {                                                // 193
    for (var i = 0; i < pattern.choices.length; ++i) {                           // 194
      try {                                                                      // 195
        checkSubtree(value, pattern.choices[i]);                                 // 196
        // No error? Yay, return.                                                // 197
        return;                                                                  // 198
      } catch (err) {                                                            // 199
        // Other errors should be thrown. Match errors just mean try another     // 200
        // choice.                                                               // 201
        if (!(err instanceof Match.Error))                                       // 202
          throw err;                                                             // 203
      }                                                                          // 204
    }                                                                            // 205
    // XXX this error is terrible                                                // 206
    throw new Match.Error("Failed Match.OneOf or Match.Optional validation");    // 207
  }                                                                              // 208
                                                                                 // 209
  // A function that isn't something we special-case is assumed to be a          // 210
  // constructor.                                                                // 211
  if (pattern instanceof Function) {                                             // 212
    if (value instanceof pattern)                                                // 213
      return;                                                                    // 214
    // XXX what if .name isn't defined                                           // 215
    throw new Match.Error("Expected " + pattern.name);                           // 216
  }                                                                              // 217
                                                                                 // 218
  var unknownKeysAllowed = false;                                                // 219
  if (pattern instanceof ObjectIncluding) {                                      // 220
    unknownKeysAllowed = true;                                                   // 221
    pattern = pattern.pattern;                                                   // 222
  }                                                                              // 223
                                                                                 // 224
  if (typeof pattern !== "object")                                               // 225
    throw Error("Bad pattern: unknown pattern type");                            // 226
                                                                                 // 227
  // An object, with required and optional keys. Note that this does NOT do      // 228
  // structural matches against objects of special types that happen to match    // 229
  // the pattern: this really needs to be a plain old {Object}!                  // 230
  if (typeof value !== 'object')                                                 // 231
    throw new Match.Error("Expected object, got " + typeof value);               // 232
  if (value === null)                                                            // 233
    throw new Match.Error("Expected object, got null");                          // 234
  if (value.constructor !== Object)                                              // 235
    throw new Match.Error("Expected plain object");                              // 236
                                                                                 // 237
  var requiredPatterns = {};                                                     // 238
  var optionalPatterns = {};                                                     // 239
  _.each(pattern, function (subPattern, key) {                                   // 240
    if (subPattern instanceof Optional)                                          // 241
      optionalPatterns[key] = subPattern.pattern;                                // 242
    else                                                                         // 243
      requiredPatterns[key] = subPattern;                                        // 244
  });                                                                            // 245
                                                                                 // 246
  _.each(value, function (subValue, key) {                                       // 247
    try {                                                                        // 248
      if (_.has(requiredPatterns, key)) {                                        // 249
        checkSubtree(subValue, requiredPatterns[key]);                           // 250
        delete requiredPatterns[key];                                            // 251
      } else if (_.has(optionalPatterns, key)) {                                 // 252
        checkSubtree(subValue, optionalPatterns[key]);                           // 253
      } else {                                                                   // 254
        if (!unknownKeysAllowed)                                                 // 255
          throw new Match.Error("Unknown key");                                  // 256
      }                                                                          // 257
    } catch (err) {                                                              // 258
      if (err instanceof Match.Error)                                            // 259
        err.path = _prependPath(key, err.path);                                  // 260
      throw err;                                                                 // 261
    }                                                                            // 262
  });                                                                            // 263
                                                                                 // 264
  _.each(requiredPatterns, function (subPattern, key) {                          // 265
    throw new Match.Error("Missing key '" + key + "'");                          // 266
  });                                                                            // 267
};                                                                               // 268
                                                                                 // 269
var ArgumentChecker = function (args, description) {                             // 270
  var self = this;                                                               // 271
  // Make a SHALLOW copy of the arguments. (We'll be doing identity checks       // 272
  // against its contents.)                                                      // 273
  self.args = _.clone(args);                                                     // 274
  // Since the common case will be to check arguments in order, and we splice    // 275
  // out arguments when we check them, make it so we splice out from the end     // 276
  // rather than the beginning.                                                  // 277
  self.args.reverse();                                                           // 278
  self.description = description;                                                // 279
};                                                                               // 280
                                                                                 // 281
_.extend(ArgumentChecker.prototype, {                                            // 282
  checking: function (value) {                                                   // 283
    var self = this;                                                             // 284
    if (self._checkingOneValue(value))                                           // 285
      return;                                                                    // 286
    // Allow check(arguments, [String]) or check(arguments.slice(1), [String])   // 287
    // or check([foo, bar], [String]) to count... but only if value wasn't       // 288
    // itself an argument.                                                       // 289
    if (_.isArray(value) || _.isArguments(value)) {                              // 290
      _.each(value, _.bind(self._checkingOneValue, self));                       // 291
    }                                                                            // 292
  },                                                                             // 293
  _checkingOneValue: function (value) {                                          // 294
    var self = this;                                                             // 295
    for (var i = 0; i < self.args.length; ++i) {                                 // 296
      // Is this value one of the arguments? (This can have a false positive if  // 297
      // the argument is an interned primitive, but it's still a good enough     // 298
      // check.)                                                                 // 299
      if (value === self.args[i]) {                                              // 300
        self.args.splice(i, 1);                                                  // 301
        return true;                                                             // 302
      }                                                                          // 303
    }                                                                            // 304
    return false;                                                                // 305
  },                                                                             // 306
  throwUnlessAllArgumentsHaveBeenChecked: function () {                          // 307
    var self = this;                                                             // 308
    if (!_.isEmpty(self.args))                                                   // 309
      throw new Error("Did not check() all arguments during " +                  // 310
                      self.description);                                         // 311
  }                                                                              // 312
});                                                                              // 313
                                                                                 // 314
var _jsKeywords = ["do", "if", "in", "for", "let", "new", "try", "var", "case",  // 315
  "else", "enum", "eval", "false", "null", "this", "true", "void", "with",       // 316
  "break", "catch", "class", "const", "super", "throw", "while", "yield",        // 317
  "delete", "export", "import", "public", "return", "static", "switch",          // 318
  "typeof", "default", "extends", "finally", "package", "private", "continue",   // 319
  "debugger", "function", "arguments", "interface", "protected", "implements",   // 320
  "instanceof"];                                                                 // 321
                                                                                 // 322
// Assumes the base of path is already escaped properly                          // 323
// returns key + base                                                            // 324
var _prependPath = function (key, base) {                                        // 325
  if ((typeof key) === "number" || key.match(/^[0-9]+$/))                        // 326
    key = "[" + key + "]";                                                       // 327
  else if (!key.match(/^[a-z_$][0-9a-z_$]*$/i) || _.contains(_jsKeywords, key))  // 328
    key = JSON.stringify([key]);                                                 // 329
                                                                                 // 330
  if (base && base[0] !== "[")                                                   // 331
    return key + '.' + base;                                                     // 332
  return key + base;                                                             // 333
};                                                                               // 334
                                                                                 // 335
                                                                                 // 336
///////////////////////////////////////////////////////////////////////////////////

}).call(this);


/* Exports */
if (typeof Package === 'undefined') Package = {};
Package.check = {
  check: check,
  Match: Match
};

})();

//# sourceMappingURL=c523809f1b6e549675209e7b75fdecd3b3bcdddf.map
