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
var JSON = Package.json.JSON;
var _ = Package.underscore._;

/* Package-scope variables */
var EJSON, EJSONTest, base64Encode, base64Decode;

(function () {

//////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                              //
// packages/ejson/ejson.js                                                                      //
//                                                                                              //
//////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                //
EJSON = {};                                                                                     // 1
EJSONTest = {};                                                                                 // 2
                                                                                                // 3
var customTypes = {};                                                                           // 4
// Add a custom type, using a method of your choice to get to and                               // 5
// from a basic JSON-able representation.  The factory argument                                 // 6
// is a function of JSON-able --> your object                                                   // 7
// The type you add must have:                                                                  // 8
// - A toJSONValue() method, so that Meteor can serialize it                                    // 9
// - a typeName() method, to show how to look it up in our type table.                          // 10
// It is okay if these methods are monkey-patched on.                                           // 11
// EJSON.clone will use toJSONValue and the given factory to produce                            // 12
// a clone, but you may specify a method clone() that will be                                   // 13
// used instead.                                                                                // 14
// Similarly, EJSON.equals will use toJSONValue to make comparisons,                            // 15
// but you may provide a method equals() instead.                                               // 16
//                                                                                              // 17
EJSON.addType = function (name, factory) {                                                      // 18
  if (_.has(customTypes, name))                                                                 // 19
    throw new Error("Type " + name + " already present");                                       // 20
  customTypes[name] = factory;                                                                  // 21
};                                                                                              // 22
                                                                                                // 23
var isInfOrNan = function (obj) {                                                               // 24
  return _.isNaN(obj) || obj === Infinity || obj === -Infinity;                                 // 25
};                                                                                              // 26
                                                                                                // 27
var builtinConverters = [                                                                       // 28
  { // Date                                                                                     // 29
    matchJSONValue: function (obj) {                                                            // 30
      return _.has(obj, '$date') && _.size(obj) === 1;                                          // 31
    },                                                                                          // 32
    matchObject: function (obj) {                                                               // 33
      return obj instanceof Date;                                                               // 34
    },                                                                                          // 35
    toJSONValue: function (obj) {                                                               // 36
      return {$date: obj.getTime()};                                                            // 37
    },                                                                                          // 38
    fromJSONValue: function (obj) {                                                             // 39
      return new Date(obj.$date);                                                               // 40
    }                                                                                           // 41
  },                                                                                            // 42
  { // NaN, Inf, -Inf. (These are the only objects with typeof !== 'object'                     // 43
    // which we match.)                                                                         // 44
    matchJSONValue: function (obj) {                                                            // 45
      return _.has(obj, '$InfNaN') && _.size(obj) === 1;                                        // 46
    },                                                                                          // 47
    matchObject: isInfOrNan,                                                                    // 48
    toJSONValue: function (obj) {                                                               // 49
      var sign;                                                                                 // 50
      if (_.isNaN(obj))                                                                         // 51
        sign = 0;                                                                               // 52
      else if (obj === Infinity)                                                                // 53
        sign = 1;                                                                               // 54
      else                                                                                      // 55
        sign = -1;                                                                              // 56
      return {$InfNaN: sign};                                                                   // 57
    },                                                                                          // 58
    fromJSONValue: function (obj) {                                                             // 59
      return obj.$InfNaN/0;                                                                     // 60
    }                                                                                           // 61
  },                                                                                            // 62
  { // Binary                                                                                   // 63
    matchJSONValue: function (obj) {                                                            // 64
      return _.has(obj, '$binary') && _.size(obj) === 1;                                        // 65
    },                                                                                          // 66
    matchObject: function (obj) {                                                               // 67
      return typeof Uint8Array !== 'undefined' && obj instanceof Uint8Array                     // 68
        || (obj && _.has(obj, '$Uint8ArrayPolyfill'));                                          // 69
    },                                                                                          // 70
    toJSONValue: function (obj) {                                                               // 71
      return {$binary: base64Encode(obj)};                                                      // 72
    },                                                                                          // 73
    fromJSONValue: function (obj) {                                                             // 74
      return base64Decode(obj.$binary);                                                         // 75
    }                                                                                           // 76
  },                                                                                            // 77
  { // Escaping one level                                                                       // 78
    matchJSONValue: function (obj) {                                                            // 79
      return _.has(obj, '$escape') && _.size(obj) === 1;                                        // 80
    },                                                                                          // 81
    matchObject: function (obj) {                                                               // 82
      if (_.isEmpty(obj) || _.size(obj) > 2) {                                                  // 83
        return false;                                                                           // 84
      }                                                                                         // 85
      return _.any(builtinConverters, function (converter) {                                    // 86
        return converter.matchJSONValue(obj);                                                   // 87
      });                                                                                       // 88
    },                                                                                          // 89
    toJSONValue: function (obj) {                                                               // 90
      var newObj = {};                                                                          // 91
      _.each(obj, function (value, key) {                                                       // 92
        newObj[key] = EJSON.toJSONValue(value);                                                 // 93
      });                                                                                       // 94
      return {$escape: newObj};                                                                 // 95
    },                                                                                          // 96
    fromJSONValue: function (obj) {                                                             // 97
      var newObj = {};                                                                          // 98
      _.each(obj.$escape, function (value, key) {                                               // 99
        newObj[key] = EJSON.fromJSONValue(value);                                               // 100
      });                                                                                       // 101
      return newObj;                                                                            // 102
    }                                                                                           // 103
  },                                                                                            // 104
  { // Custom                                                                                   // 105
    matchJSONValue: function (obj) {                                                            // 106
      return _.has(obj, '$type') && _.has(obj, '$value') && _.size(obj) === 2;                  // 107
    },                                                                                          // 108
    matchObject: function (obj) {                                                               // 109
      return EJSON._isCustomType(obj);                                                          // 110
    },                                                                                          // 111
    toJSONValue: function (obj) {                                                               // 112
      var jsonValue = Meteor._noYieldsAllowed(function () {                                     // 113
        return obj.toJSONValue();                                                               // 114
      });                                                                                       // 115
      return {$type: obj.typeName(), $value: jsonValue};                                        // 116
    },                                                                                          // 117
    fromJSONValue: function (obj) {                                                             // 118
      var typeName = obj.$type;                                                                 // 119
      if (!_.has(customTypes, typeName))                                                        // 120
        throw new Error("Custom EJSON type " + typeName + " is not defined");                   // 121
      var converter = customTypes[typeName];                                                    // 122
      return Meteor._noYieldsAllowed(function () {                                              // 123
        return converter(obj.$value);                                                           // 124
      });                                                                                       // 125
    }                                                                                           // 126
  }                                                                                             // 127
];                                                                                              // 128
                                                                                                // 129
EJSON._isCustomType = function (obj) {                                                          // 130
  return obj &&                                                                                 // 131
    typeof obj.toJSONValue === 'function' &&                                                    // 132
    typeof obj.typeName === 'function' &&                                                       // 133
    _.has(customTypes, obj.typeName());                                                         // 134
};                                                                                              // 135
                                                                                                // 136
                                                                                                // 137
// for both arrays and objects, in-place modification.                                          // 138
var adjustTypesToJSONValue =                                                                    // 139
EJSON._adjustTypesToJSONValue = function (obj) {                                                // 140
  // Is it an atom that we need to adjust?                                                      // 141
  if (obj === null)                                                                             // 142
    return null;                                                                                // 143
  var maybeChanged = toJSONValueHelper(obj);                                                    // 144
  if (maybeChanged !== undefined)                                                               // 145
    return maybeChanged;                                                                        // 146
                                                                                                // 147
  // Other atoms are unchanged.                                                                 // 148
  if (typeof obj !== 'object')                                                                  // 149
    return obj;                                                                                 // 150
                                                                                                // 151
  // Iterate over array or object structure.                                                    // 152
  _.each(obj, function (value, key) {                                                           // 153
    if (typeof value !== 'object' && value !== undefined &&                                     // 154
        !isInfOrNan(value))                                                                     // 155
      return; // continue                                                                       // 156
                                                                                                // 157
    var changed = toJSONValueHelper(value);                                                     // 158
    if (changed) {                                                                              // 159
      obj[key] = changed;                                                                       // 160
      return; // on to the next key                                                             // 161
    }                                                                                           // 162
    // if we get here, value is an object but not adjustable                                    // 163
    // at this level.  recurse.                                                                 // 164
    adjustTypesToJSONValue(value);                                                              // 165
  });                                                                                           // 166
  return obj;                                                                                   // 167
};                                                                                              // 168
                                                                                                // 169
// Either return the JSON-compatible version of the argument, or undefined (if                  // 170
// the item isn't itself replaceable, but maybe some fields in it are)                          // 171
var toJSONValueHelper = function (item) {                                                       // 172
  for (var i = 0; i < builtinConverters.length; i++) {                                          // 173
    var converter = builtinConverters[i];                                                       // 174
    if (converter.matchObject(item)) {                                                          // 175
      return converter.toJSONValue(item);                                                       // 176
    }                                                                                           // 177
  }                                                                                             // 178
  return undefined;                                                                             // 179
};                                                                                              // 180
                                                                                                // 181
EJSON.toJSONValue = function (item) {                                                           // 182
  var changed = toJSONValueHelper(item);                                                        // 183
  if (changed !== undefined)                                                                    // 184
    return changed;                                                                             // 185
  if (typeof item === 'object') {                                                               // 186
    item = EJSON.clone(item);                                                                   // 187
    adjustTypesToJSONValue(item);                                                               // 188
  }                                                                                             // 189
  return item;                                                                                  // 190
};                                                                                              // 191
                                                                                                // 192
// for both arrays and objects. Tries its best to just                                          // 193
// use the object you hand it, but may return something                                         // 194
// different if the object you hand it itself needs changing.                                   // 195
//                                                                                              // 196
var adjustTypesFromJSONValue =                                                                  // 197
EJSON._adjustTypesFromJSONValue = function (obj) {                                              // 198
  if (obj === null)                                                                             // 199
    return null;                                                                                // 200
  var maybeChanged = fromJSONValueHelper(obj);                                                  // 201
  if (maybeChanged !== obj)                                                                     // 202
    return maybeChanged;                                                                        // 203
                                                                                                // 204
  // Other atoms are unchanged.                                                                 // 205
  if (typeof obj !== 'object')                                                                  // 206
    return obj;                                                                                 // 207
                                                                                                // 208
  _.each(obj, function (value, key) {                                                           // 209
    if (typeof value === 'object') {                                                            // 210
      var changed = fromJSONValueHelper(value);                                                 // 211
      if (value !== changed) {                                                                  // 212
        obj[key] = changed;                                                                     // 213
        return;                                                                                 // 214
      }                                                                                         // 215
      // if we get here, value is an object but not adjustable                                  // 216
      // at this level.  recurse.                                                               // 217
      adjustTypesFromJSONValue(value);                                                          // 218
    }                                                                                           // 219
  });                                                                                           // 220
  return obj;                                                                                   // 221
};                                                                                              // 222
                                                                                                // 223
// Either return the argument changed to have the non-json                                      // 224
// rep of itself (the Object version) or the argument itself.                                   // 225
                                                                                                // 226
// DOES NOT RECURSE.  For actually getting the fully-changed value, use                         // 227
// EJSON.fromJSONValue                                                                          // 228
var fromJSONValueHelper = function (value) {                                                    // 229
  if (typeof value === 'object' && value !== null) {                                            // 230
    if (_.size(value) <= 2                                                                      // 231
        && _.all(value, function (v, k) {                                                       // 232
          return typeof k === 'string' && k.substr(0, 1) === '$';                               // 233
        })) {                                                                                   // 234
      for (var i = 0; i < builtinConverters.length; i++) {                                      // 235
        var converter = builtinConverters[i];                                                   // 236
        if (converter.matchJSONValue(value)) {                                                  // 237
          return converter.fromJSONValue(value);                                                // 238
        }                                                                                       // 239
      }                                                                                         // 240
    }                                                                                           // 241
  }                                                                                             // 242
  return value;                                                                                 // 243
};                                                                                              // 244
                                                                                                // 245
EJSON.fromJSONValue = function (item) {                                                         // 246
  var changed = fromJSONValueHelper(item);                                                      // 247
  if (changed === item && typeof item === 'object') {                                           // 248
    item = EJSON.clone(item);                                                                   // 249
    adjustTypesFromJSONValue(item);                                                             // 250
    return item;                                                                                // 251
  } else {                                                                                      // 252
    return changed;                                                                             // 253
  }                                                                                             // 254
};                                                                                              // 255
                                                                                                // 256
EJSON.stringify = function (item, options) {                                                    // 257
  var json = EJSON.toJSONValue(item);                                                           // 258
  if (options && (options.canonical || options.indent)) {                                       // 259
    return EJSON._canonicalStringify(json, options);                                            // 260
  } else {                                                                                      // 261
    return JSON.stringify(json);                                                                // 262
  }                                                                                             // 263
};                                                                                              // 264
                                                                                                // 265
EJSON.parse = function (item) {                                                                 // 266
  if (typeof item !== 'string')                                                                 // 267
    throw new Error("EJSON.parse argument should be a string");                                 // 268
  return EJSON.fromJSONValue(JSON.parse(item));                                                 // 269
};                                                                                              // 270
                                                                                                // 271
EJSON.isBinary = function (obj) {                                                               // 272
  return !!((typeof Uint8Array !== 'undefined' && obj instanceof Uint8Array) ||                 // 273
    (obj && obj.$Uint8ArrayPolyfill));                                                          // 274
};                                                                                              // 275
                                                                                                // 276
EJSON.equals = function (a, b, options) {                                                       // 277
  var i;                                                                                        // 278
  var keyOrderSensitive = !!(options && options.keyOrderSensitive);                             // 279
  if (a === b)                                                                                  // 280
    return true;                                                                                // 281
  if (_.isNaN(a) && _.isNaN(b))                                                                 // 282
    return true; // This differs from the IEEE spec for NaN equality, b/c we don't want         // 283
                 // anything ever with a NaN to be poisoned from becoming equal to anything.    // 284
  if (!a || !b) // if either one is falsy, they'd have to be === to be equal                    // 285
    return false;                                                                               // 286
  if (!(typeof a === 'object' && typeof b === 'object'))                                        // 287
    return false;                                                                               // 288
  if (a instanceof Date && b instanceof Date)                                                   // 289
    return a.valueOf() === b.valueOf();                                                         // 290
  if (EJSON.isBinary(a) && EJSON.isBinary(b)) {                                                 // 291
    if (a.length !== b.length)                                                                  // 292
      return false;                                                                             // 293
    for (i = 0; i < a.length; i++) {                                                            // 294
      if (a[i] !== b[i])                                                                        // 295
        return false;                                                                           // 296
    }                                                                                           // 297
    return true;                                                                                // 298
  }                                                                                             // 299
  if (typeof (a.equals) === 'function')                                                         // 300
    return a.equals(b, options);                                                                // 301
  if (typeof (b.equals) === 'function')                                                         // 302
    return b.equals(a, options);                                                                // 303
  if (a instanceof Array) {                                                                     // 304
    if (!(b instanceof Array))                                                                  // 305
      return false;                                                                             // 306
    if (a.length !== b.length)                                                                  // 307
      return false;                                                                             // 308
    for (i = 0; i < a.length; i++) {                                                            // 309
      if (!EJSON.equals(a[i], b[i], options))                                                   // 310
        return false;                                                                           // 311
    }                                                                                           // 312
    return true;                                                                                // 313
  }                                                                                             // 314
  // fallback for custom types that don't implement their own equals                            // 315
  switch (EJSON._isCustomType(a) + EJSON._isCustomType(b)) {                                    // 316
    case 1: return false;                                                                       // 317
    case 2: return EJSON.equals(EJSON.toJSONValue(a), EJSON.toJSONValue(b));                    // 318
  }                                                                                             // 319
  // fall back to structural equality of objects                                                // 320
  var ret;                                                                                      // 321
  if (keyOrderSensitive) {                                                                      // 322
    var bKeys = [];                                                                             // 323
    _.each(b, function (val, x) {                                                               // 324
        bKeys.push(x);                                                                          // 325
    });                                                                                         // 326
    i = 0;                                                                                      // 327
    ret = _.all(a, function (val, x) {                                                          // 328
      if (i >= bKeys.length) {                                                                  // 329
        return false;                                                                           // 330
      }                                                                                         // 331
      if (x !== bKeys[i]) {                                                                     // 332
        return false;                                                                           // 333
      }                                                                                         // 334
      if (!EJSON.equals(val, b[bKeys[i]], options)) {                                           // 335
        return false;                                                                           // 336
      }                                                                                         // 337
      i++;                                                                                      // 338
      return true;                                                                              // 339
    });                                                                                         // 340
    return ret && i === bKeys.length;                                                           // 341
  } else {                                                                                      // 342
    i = 0;                                                                                      // 343
    ret = _.all(a, function (val, key) {                                                        // 344
      if (!_.has(b, key)) {                                                                     // 345
        return false;                                                                           // 346
      }                                                                                         // 347
      if (!EJSON.equals(val, b[key], options)) {                                                // 348
        return false;                                                                           // 349
      }                                                                                         // 350
      i++;                                                                                      // 351
      return true;                                                                              // 352
    });                                                                                         // 353
    return ret && _.size(b) === i;                                                              // 354
  }                                                                                             // 355
};                                                                                              // 356
                                                                                                // 357
EJSON.clone = function (v) {                                                                    // 358
  var ret;                                                                                      // 359
  if (typeof v !== "object")                                                                    // 360
    return v;                                                                                   // 361
  if (v === null)                                                                               // 362
    return null; // null has typeof "object"                                                    // 363
  if (v instanceof Date)                                                                        // 364
    return new Date(v.getTime());                                                               // 365
  // RegExps are not really EJSON elements (eg we don't define a serialization                  // 366
  // for them), but they're immutable anyway, so we can support them in clone.                  // 367
  if (v instanceof RegExp)                                                                      // 368
    return v;                                                                                   // 369
  if (EJSON.isBinary(v)) {                                                                      // 370
    ret = EJSON.newBinary(v.length);                                                            // 371
    for (var i = 0; i < v.length; i++) {                                                        // 372
      ret[i] = v[i];                                                                            // 373
    }                                                                                           // 374
    return ret;                                                                                 // 375
  }                                                                                             // 376
  // XXX: Use something better than underscore's isArray                                        // 377
  if (_.isArray(v) || _.isArguments(v)) {                                                       // 378
    // For some reason, _.map doesn't work in this context on Opera (weird test                 // 379
    // failures).                                                                               // 380
    ret = [];                                                                                   // 381
    for (i = 0; i < v.length; i++)                                                              // 382
      ret[i] = EJSON.clone(v[i]);                                                               // 383
    return ret;                                                                                 // 384
  }                                                                                             // 385
  // handle general user-defined typed Objects if they have a clone method                      // 386
  if (typeof v.clone === 'function') {                                                          // 387
    return v.clone();                                                                           // 388
  }                                                                                             // 389
  // handle other custom types                                                                  // 390
  if (EJSON._isCustomType(v)) {                                                                 // 391
    return EJSON.fromJSONValue(EJSON.clone(EJSON.toJSONValue(v)), true);                        // 392
  }                                                                                             // 393
  // handle other objects                                                                       // 394
  ret = {};                                                                                     // 395
  _.each(v, function (value, key) {                                                             // 396
    ret[key] = EJSON.clone(value);                                                              // 397
  });                                                                                           // 398
  return ret;                                                                                   // 399
};                                                                                              // 400
                                                                                                // 401
//////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

//////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                              //
// packages/ejson/stringify.js                                                                  //
//                                                                                              //
//////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                //
// Based on json2.js from https://github.com/douglascrockford/JSON-js                           // 1
//                                                                                              // 2
//    json2.js                                                                                  // 3
//    2012-10-08                                                                                // 4
//                                                                                              // 5
//    Public Domain.                                                                            // 6
//                                                                                              // 7
//    NO WARRANTY EXPRESSED OR IMPLIED. USE AT YOUR OWN RISK.                                   // 8
                                                                                                // 9
function quote(string) {                                                                        // 10
  return JSON.stringify(string);                                                                // 11
}                                                                                               // 12
                                                                                                // 13
var str = function (key, holder, singleIndent, outerIndent, canonical) {                        // 14
                                                                                                // 15
  // Produce a string from holder[key].                                                         // 16
                                                                                                // 17
  var i;          // The loop counter.                                                          // 18
  var k;          // The member key.                                                            // 19
  var v;          // The member value.                                                          // 20
  var length;                                                                                   // 21
  var innerIndent = outerIndent;                                                                // 22
  var partial;                                                                                  // 23
  var value = holder[key];                                                                      // 24
                                                                                                // 25
  // What happens next depends on the value's type.                                             // 26
                                                                                                // 27
  switch (typeof value) {                                                                       // 28
  case 'string':                                                                                // 29
    return quote(value);                                                                        // 30
  case 'number':                                                                                // 31
    // JSON numbers must be finite. Encode non-finite numbers as null.                          // 32
    return isFinite(value) ? String(value) : 'null';                                            // 33
  case 'boolean':                                                                               // 34
    return String(value);                                                                       // 35
  // If the type is 'object', we might be dealing with an object or an array or                 // 36
  // null.                                                                                      // 37
  case 'object':                                                                                // 38
    // Due to a specification blunder in ECMAScript, typeof null is 'object',                   // 39
    // so watch out for that case.                                                              // 40
    if (!value) {                                                                               // 41
      return 'null';                                                                            // 42
    }                                                                                           // 43
    // Make an array to hold the partial results of stringifying this object value.             // 44
    innerIndent = outerIndent + singleIndent;                                                   // 45
    partial = [];                                                                               // 46
                                                                                                // 47
    // Is the value an array?                                                                   // 48
    if (_.isArray(value) || _.isArguments(value)) {                                             // 49
                                                                                                // 50
      // The value is an array. Stringify every element. Use null as a placeholder              // 51
      // for non-JSON values.                                                                   // 52
                                                                                                // 53
      length = value.length;                                                                    // 54
      for (i = 0; i < length; i += 1) {                                                         // 55
        partial[i] = str(i, value, singleIndent, innerIndent, canonical) || 'null';             // 56
      }                                                                                         // 57
                                                                                                // 58
      // Join all of the elements together, separated with commas, and wrap them in             // 59
      // brackets.                                                                              // 60
                                                                                                // 61
      if (partial.length === 0) {                                                               // 62
        v = '[]';                                                                               // 63
      } else if (innerIndent) {                                                                 // 64
        v = '[\n' + innerIndent + partial.join(',\n' + innerIndent) + '\n' + outerIndent + ']'; // 65
      } else {                                                                                  // 66
        v = '[' + partial.join(',') + ']';                                                      // 67
      }                                                                                         // 68
      return v;                                                                                 // 69
    }                                                                                           // 70
                                                                                                // 71
                                                                                                // 72
    // Iterate through all of the keys in the object.                                           // 73
    var keys = _.keys(value);                                                                   // 74
    if (canonical)                                                                              // 75
      keys = keys.sort();                                                                       // 76
    _.each(keys, function (k) {                                                                 // 77
      v = str(k, value, singleIndent, innerIndent, canonical);                                  // 78
      if (v) {                                                                                  // 79
        partial.push(quote(k) + (innerIndent ? ': ' : ':') + v);                                // 80
      }                                                                                         // 81
    });                                                                                         // 82
                                                                                                // 83
                                                                                                // 84
    // Join all of the member texts together, separated with commas,                            // 85
    // and wrap them in braces.                                                                 // 86
                                                                                                // 87
    if (partial.length === 0) {                                                                 // 88
      v = '{}';                                                                                 // 89
    } else if (innerIndent) {                                                                   // 90
      v = '{\n' + innerIndent + partial.join(',\n' + innerIndent) + '\n' + outerIndent + '}';   // 91
    } else {                                                                                    // 92
      v = '{' + partial.join(',') + '}';                                                        // 93
    }                                                                                           // 94
    return v;                                                                                   // 95
  }                                                                                             // 96
}                                                                                               // 97
                                                                                                // 98
// If the JSON object does not yet have a stringify method, give it one.                        // 99
                                                                                                // 100
EJSON._canonicalStringify = function (value, options) {                                         // 101
  // Make a fake root object containing our value under the key of ''.                          // 102
  // Return the result of stringifying the value.                                               // 103
  options = _.extend({                                                                          // 104
    indent: "",                                                                                 // 105
    canonical: false                                                                            // 106
  }, options);                                                                                  // 107
  if (options.indent === true) {                                                                // 108
    options.indent = "  ";                                                                      // 109
  } else if (typeof options.indent === 'number') {                                              // 110
    var newIndent = "";                                                                         // 111
    for (var i = 0; i < options.indent; i++) {                                                  // 112
      newIndent += ' ';                                                                         // 113
    }                                                                                           // 114
    options.indent = newIndent;                                                                 // 115
  }                                                                                             // 116
  return str('', {'': value}, options.indent, "", options.canonical);                           // 117
};                                                                                              // 118
                                                                                                // 119
//////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

//////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                              //
// packages/ejson/base64.js                                                                     //
//                                                                                              //
//////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                //
// Base 64 encoding                                                                             // 1
                                                                                                // 2
var BASE_64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";         // 3
                                                                                                // 4
var BASE_64_VALS = {};                                                                          // 5
                                                                                                // 6
for (var i = 0; i < BASE_64_CHARS.length; i++) {                                                // 7
  BASE_64_VALS[BASE_64_CHARS.charAt(i)] = i;                                                    // 8
};                                                                                              // 9
                                                                                                // 10
base64Encode = function (array) {                                                               // 11
  var answer = [];                                                                              // 12
  var a = null;                                                                                 // 13
  var b = null;                                                                                 // 14
  var c = null;                                                                                 // 15
  var d = null;                                                                                 // 16
  for (var i = 0; i < array.length; i++) {                                                      // 17
    switch (i % 3) {                                                                            // 18
    case 0:                                                                                     // 19
      a = (array[i] >> 2) & 0x3F;                                                               // 20
      b = (array[i] & 0x03) << 4;                                                               // 21
      break;                                                                                    // 22
    case 1:                                                                                     // 23
      b = b | (array[i] >> 4) & 0xF;                                                            // 24
      c = (array[i] & 0xF) << 2;                                                                // 25
      break;                                                                                    // 26
    case 2:                                                                                     // 27
      c = c | (array[i] >> 6) & 0x03;                                                           // 28
      d = array[i] & 0x3F;                                                                      // 29
      answer.push(getChar(a));                                                                  // 30
      answer.push(getChar(b));                                                                  // 31
      answer.push(getChar(c));                                                                  // 32
      answer.push(getChar(d));                                                                  // 33
      a = null;                                                                                 // 34
      b = null;                                                                                 // 35
      c = null;                                                                                 // 36
      d = null;                                                                                 // 37
      break;                                                                                    // 38
    }                                                                                           // 39
  }                                                                                             // 40
  if (a != null) {                                                                              // 41
    answer.push(getChar(a));                                                                    // 42
    answer.push(getChar(b));                                                                    // 43
    if (c == null)                                                                              // 44
      answer.push('=');                                                                         // 45
    else                                                                                        // 46
      answer.push(getChar(c));                                                                  // 47
    if (d == null)                                                                              // 48
      answer.push('=');                                                                         // 49
  }                                                                                             // 50
  return answer.join("");                                                                       // 51
};                                                                                              // 52
                                                                                                // 53
var getChar = function (val) {                                                                  // 54
  return BASE_64_CHARS.charAt(val);                                                             // 55
};                                                                                              // 56
                                                                                                // 57
var getVal = function (ch) {                                                                    // 58
  if (ch === '=') {                                                                             // 59
    return -1;                                                                                  // 60
  }                                                                                             // 61
  return BASE_64_VALS[ch];                                                                      // 62
};                                                                                              // 63
                                                                                                // 64
EJSON.newBinary = function (len) {                                                              // 65
  if (typeof Uint8Array === 'undefined' || typeof ArrayBuffer === 'undefined') {                // 66
    var ret = [];                                                                               // 67
    for (var i = 0; i < len; i++) {                                                             // 68
      ret.push(0);                                                                              // 69
    }                                                                                           // 70
    ret.$Uint8ArrayPolyfill = true;                                                             // 71
    return ret;                                                                                 // 72
  }                                                                                             // 73
  return new Uint8Array(new ArrayBuffer(len));                                                  // 74
};                                                                                              // 75
                                                                                                // 76
base64Decode = function (str) {                                                                 // 77
  var len = Math.floor((str.length*3)/4);                                                       // 78
  if (str.charAt(str.length - 1) == '=') {                                                      // 79
    len--;                                                                                      // 80
    if (str.charAt(str.length - 2) == '=')                                                      // 81
      len--;                                                                                    // 82
  }                                                                                             // 83
  var arr = EJSON.newBinary(len);                                                               // 84
                                                                                                // 85
  var one = null;                                                                               // 86
  var two = null;                                                                               // 87
  var three = null;                                                                             // 88
                                                                                                // 89
  var j = 0;                                                                                    // 90
                                                                                                // 91
  for (var i = 0; i < str.length; i++) {                                                        // 92
    var c = str.charAt(i);                                                                      // 93
    var v = getVal(c);                                                                          // 94
    switch (i % 4) {                                                                            // 95
    case 0:                                                                                     // 96
      if (v < 0)                                                                                // 97
        throw new Error('invalid base64 string');                                               // 98
      one = v << 2;                                                                             // 99
      break;                                                                                    // 100
    case 1:                                                                                     // 101
      if (v < 0)                                                                                // 102
        throw new Error('invalid base64 string');                                               // 103
      one = one | (v >> 4);                                                                     // 104
      arr[j++] = one;                                                                           // 105
      two = (v & 0x0F) << 4;                                                                    // 106
      break;                                                                                    // 107
    case 2:                                                                                     // 108
      if (v >= 0) {                                                                             // 109
        two = two | (v >> 2);                                                                   // 110
        arr[j++] = two;                                                                         // 111
        three = (v & 0x03) << 6;                                                                // 112
      }                                                                                         // 113
      break;                                                                                    // 114
    case 3:                                                                                     // 115
      if (v >= 0) {                                                                             // 116
        arr[j++] = three | v;                                                                   // 117
      }                                                                                         // 118
      break;                                                                                    // 119
    }                                                                                           // 120
  }                                                                                             // 121
  return arr;                                                                                   // 122
};                                                                                              // 123
                                                                                                // 124
EJSONTest.base64Encode = base64Encode;                                                          // 125
                                                                                                // 126
EJSONTest.base64Decode = base64Decode;                                                          // 127
                                                                                                // 128
//////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);


/* Exports */
if (typeof Package === 'undefined') Package = {};
Package.ejson = {
  EJSON: EJSON,
  EJSONTest: EJSONTest
};

})();

//# sourceMappingURL=9ccd48dbafd805e21408c9eae1061468b3ec1f2f.map
