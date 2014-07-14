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
var Deps = Package.deps.Deps;
var LocalCollection = Package.minimongo.LocalCollection;
var Minimongo = Package.minimongo.Minimongo;
var _ = Package.underscore._;
var Random = Package.random.Random;

/* Package-scope variables */
var ObserveSequence;

(function () {

//////////////////////////////////////////////////////////////////////////////////////////
//                                                                                      //
// packages/observe-sequence/observe_sequence.js                                        //
//                                                                                      //
//////////////////////////////////////////////////////////////////////////////////////////
                                                                                        //
var warn = function () {                                                                // 1
  if (ObserveSequence._suppressWarnings) {                                              // 2
    ObserveSequence._suppressWarnings--;                                                // 3
  } else {                                                                              // 4
    if (typeof console !== 'undefined' && console.warn)                                 // 5
      console.warn.apply(console, arguments);                                           // 6
                                                                                        // 7
    ObserveSequence._loggedWarnings++;                                                  // 8
  }                                                                                     // 9
};                                                                                      // 10
                                                                                        // 11
var idStringify = LocalCollection._idStringify;                                         // 12
var idParse = LocalCollection._idParse;                                                 // 13
                                                                                        // 14
ObserveSequence = {                                                                     // 15
  _suppressWarnings: 0,                                                                 // 16
  _loggedWarnings: 0,                                                                   // 17
                                                                                        // 18
  // A mechanism similar to cursor.observe which receives a reactive                    // 19
  // function returning a sequence type and firing appropriate callbacks                // 20
  // when the value changes.                                                            // 21
  //                                                                                    // 22
  // @param sequenceFunc {Function} a reactive function returning a                     // 23
  //     sequence type. The currently supported sequence types are:                     // 24
  //     'null', arrays and cursors.                                                    // 25
  //                                                                                    // 26
  // @param callbacks {Object} similar to a specific subset of                          // 27
  //     callbacks passed to `cursor.observe`                                           // 28
  //     (http://docs.meteor.com/#observe), with minor variations to                    // 29
  //     support the fact that not all sequences contain objects with                   // 30
  //     _id fields.  Specifically:                                                     // 31
  //                                                                                    // 32
  //     * addedAt(id, item, atIndex, beforeId)                                         // 33
  //     * changedAt(id, newItem, oldItem, atIndex)                                     // 34
  //     * removedAt(id, oldItem, atIndex)                                              // 35
  //     * movedTo(id, item, fromIndex, toIndex, beforeId)                              // 36
  //                                                                                    // 37
  // @returns {Object(stop: Function)} call 'stop' on the return value                  // 38
  //     to stop observing this sequence function.                                      // 39
  //                                                                                    // 40
  // We don't make any assumptions about our ability to compare sequence                // 41
  // elements (ie, we don't assume EJSON.equals works; maybe there is extra             // 42
  // state/random methods on the objects) so unlike cursor.observe, we may              // 43
  // sometimes call changedAt() when nothing actually changed.                          // 44
  // XXX consider if we *can* make the stronger assumption and avoid                    // 45
  //     no-op changedAt calls (in some cases?)                                         // 46
  //                                                                                    // 47
  // XXX currently only supports the callbacks used by our                              // 48
  // implementation of {{#each}}, but this can be expanded.                             // 49
  //                                                                                    // 50
  // XXX #each doesn't use the indices (though we'll eventually need                    // 51
  // a way to get them when we support `@index`), but calling                           // 52
  // `cursor.observe` causes the index to be calculated on every                        // 53
  // callback using a linear scan (unless you turn it off by passing                    // 54
  // `_no_indices`).  Any way to avoid calculating indices on a pure                    // 55
  // cursor observe like we used to?                                                    // 56
  observe: function (sequenceFunc, callbacks) {                                         // 57
    var lastSeq = null;                                                                 // 58
    var activeObserveHandle = null;                                                     // 59
                                                                                        // 60
    // 'lastSeqArray' contains the previous value of the sequence                       // 61
    // we're observing. It is an array of objects with '_id' and                        // 62
    // 'item' fields.  'item' is the element in the array, or the                       // 63
    // document in the cursor.                                                          // 64
    //                                                                                  // 65
    // '_id' is whichever of the following is relevant, unless it has                   // 66
    // already appeared -- in which case it's randomly generated.                       // 67
    //                                                                                  // 68
    // * if 'item' is an object:                                                        // 69
    //   * an '_id' field, if present                                                   // 70
    //   * otherwise, the index in the array                                            // 71
    //                                                                                  // 72
    // * if 'item' is a number or string, use that value                                // 73
    //                                                                                  // 74
    // XXX this can be generalized by allowing {{#each}} to accept a                    // 75
    // general 'key' argument which could be a function, a dotted                       // 76
    // field name, or the special @index value.                                         // 77
    var lastSeqArray = []; // elements are objects of form {_id, item}                  // 78
    var computation = Deps.autorun(function () {                                        // 79
      var seq = sequenceFunc();                                                         // 80
                                                                                        // 81
      Deps.nonreactive(function () {                                                    // 82
        var seqArray; // same structure as `lastSeqArray` above.                        // 83
                                                                                        // 84
        // If we were previously observing a cursor, replace lastSeqArray with          // 85
        // more up-to-date information (specifically, the state of the observe          // 86
        // before it was stopped, which may be older than the DB).                      // 87
        if (activeObserveHandle) {                                                      // 88
          lastSeqArray = _.map(activeObserveHandle._fetch(), function (doc) {           // 89
            return {_id: doc._id, item: doc};                                           // 90
          });                                                                           // 91
          activeObserveHandle.stop();                                                   // 92
          activeObserveHandle = null;                                                   // 93
        }                                                                               // 94
                                                                                        // 95
        if (!seq) {                                                                     // 96
          seqArray = [];                                                                // 97
          diffArray(lastSeqArray, seqArray, callbacks);                                 // 98
        } else if (seq instanceof Array) {                                              // 99
          var idsUsed = {};                                                             // 100
          seqArray = _.map(seq, function (item, index) {                                // 101
            var id;                                                                     // 102
            if (typeof item === 'string') {                                             // 103
              // ensure not empty, since other layers (eg DomRange) assume this as well // 104
              id = "-" + item;                                                          // 105
            } else if (typeof item === 'number' ||                                      // 106
                       typeof item === 'boolean' ||                                     // 107
                       item === undefined) {                                            // 108
              id = item;                                                                // 109
            } else if (typeof item === 'object') {                                      // 110
              id = (item && item._id) || index;                                         // 111
            } else {                                                                    // 112
              throw new Error("{{#each}} doesn't support arrays with " +                // 113
                              "elements of type " + typeof item);                       // 114
            }                                                                           // 115
                                                                                        // 116
            var idString = idStringify(id);                                             // 117
            if (idsUsed[idString]) {                                                    // 118
              warn("duplicate id " + id + " in", seq);                                  // 119
              id = Random.id();                                                         // 120
            } else {                                                                    // 121
              idsUsed[idString] = true;                                                 // 122
            }                                                                           // 123
                                                                                        // 124
            return { _id: id, item: item };                                             // 125
          });                                                                           // 126
                                                                                        // 127
          diffArray(lastSeqArray, seqArray, callbacks);                                 // 128
        } else if (isMinimongoCursor(seq)) {                                            // 129
          var cursor = seq;                                                             // 130
          seqArray = [];                                                                // 131
                                                                                        // 132
          var initial = true; // are we observing initial data from cursor?             // 133
          activeObserveHandle = cursor.observe({                                        // 134
            addedAt: function (document, atIndex, before) {                             // 135
              if (initial) {                                                            // 136
                // keep track of initial data so that we can diff once                  // 137
                // we exit `observe`.                                                   // 138
                if (before !== null)                                                    // 139
                  throw new Error("Expected initial data from observe in order");       // 140
                seqArray.push({ _id: document._id, item: document });                   // 141
              } else {                                                                  // 142
                callbacks.addedAt(document._id, document, atIndex, before);             // 143
              }                                                                         // 144
            },                                                                          // 145
            changedAt: function (newDocument, oldDocument, atIndex) {                   // 146
              callbacks.changedAt(newDocument._id, newDocument, oldDocument,            // 147
                                  atIndex);                                             // 148
            },                                                                          // 149
            removedAt: function (oldDocument, atIndex) {                                // 150
              callbacks.removedAt(oldDocument._id, oldDocument, atIndex);               // 151
            },                                                                          // 152
            movedTo: function (document, fromIndex, toIndex, before) {                  // 153
              callbacks.movedTo(                                                        // 154
                document._id, document, fromIndex, toIndex, before);                    // 155
            }                                                                           // 156
          });                                                                           // 157
          initial = false;                                                              // 158
                                                                                        // 159
          // diff the old sequnce with initial data in the new cursor. this will        // 160
          // fire `addedAt` callbacks on the initial data.                              // 161
          diffArray(lastSeqArray, seqArray, callbacks);                                 // 162
                                                                                        // 163
        } else {                                                                        // 164
          throw badSequenceError();                                                     // 165
        }                                                                               // 166
                                                                                        // 167
        lastSeq = seq;                                                                  // 168
        lastSeqArray = seqArray;                                                        // 169
      });                                                                               // 170
    });                                                                                 // 171
                                                                                        // 172
    return {                                                                            // 173
      stop: function () {                                                               // 174
        computation.stop();                                                             // 175
        if (activeObserveHandle)                                                        // 176
          activeObserveHandle.stop();                                                   // 177
      }                                                                                 // 178
    };                                                                                  // 179
  },                                                                                    // 180
                                                                                        // 181
  // Fetch the items of `seq` into an array, where `seq` is of one of the               // 182
  // sequence types accepted by `observe`.  If `seq` is a cursor, a                     // 183
  // dependency is established.                                                         // 184
  fetch: function (seq) {                                                               // 185
    if (!seq) {                                                                         // 186
      return [];                                                                        // 187
    } else if (seq instanceof Array) {                                                  // 188
      return seq;                                                                       // 189
    } else if (isMinimongoCursor(seq)) {                                                // 190
      return seq.fetch();                                                               // 191
    } else {                                                                            // 192
      throw badSequenceError();                                                         // 193
    }                                                                                   // 194
  }                                                                                     // 195
};                                                                                      // 196
                                                                                        // 197
var badSequenceError = function () {                                                    // 198
  return new Error("{{#each}} currently only accepts " +                                // 199
                   "arrays, cursors or falsey values.");                                // 200
};                                                                                      // 201
                                                                                        // 202
var isMinimongoCursor = function (seq) {                                                // 203
  var minimongo = Package.minimongo;                                                    // 204
  return !!minimongo && (seq instanceof minimongo.LocalCollection.Cursor);              // 205
};                                                                                      // 206
                                                                                        // 207
// Calculates the differences between `lastSeqArray` and                                // 208
// `seqArray` and calls appropriate functions from `callbacks`.                         // 209
// Reuses Minimongo's diff algorithm implementation.                                    // 210
var diffArray = function (lastSeqArray, seqArray, callbacks) {                          // 211
  var diffFn = Package.minimongo.LocalCollection._diffQueryOrderedChanges;              // 212
  var oldIdObjects = [];                                                                // 213
  var newIdObjects = [];                                                                // 214
  var posOld = {}; // maps from idStringify'd ids                                       // 215
  var posNew = {}; // ditto                                                             // 216
  var posCur = {};                                                                      // 217
  var lengthCur = lastSeqArray.length;                                                  // 218
                                                                                        // 219
  _.each(seqArray, function (doc, i) {                                                  // 220
    newIdObjects.push({_id: doc._id});                                                  // 221
    posNew[idStringify(doc._id)] = i;                                                   // 222
  });                                                                                   // 223
  _.each(lastSeqArray, function (doc, i) {                                              // 224
    oldIdObjects.push({_id: doc._id});                                                  // 225
    posOld[idStringify(doc._id)] = i;                                                   // 226
    posCur[idStringify(doc._id)] = i;                                                   // 227
  });                                                                                   // 228
                                                                                        // 229
  // Arrays can contain arbitrary objects. We don't diff the                            // 230
  // objects. Instead we always fire 'changedAt' callback on every                      // 231
  // object. The consumer of `observe-sequence` should deal with                        // 232
  // it appropriately.                                                                  // 233
  diffFn(oldIdObjects, newIdObjects, {                                                  // 234
    addedBefore: function (id, doc, before) {                                           // 235
      var position = before ? posCur[idStringify(before)] : lengthCur;                  // 236
                                                                                        // 237
      _.each(posCur, function (pos, id) {                                               // 238
        if (pos >= position)                                                            // 239
          posCur[id]++;                                                                 // 240
      });                                                                               // 241
                                                                                        // 242
      lengthCur++;                                                                      // 243
      posCur[idStringify(id)] = position;                                               // 244
                                                                                        // 245
      callbacks.addedAt(                                                                // 246
        id,                                                                             // 247
        seqArray[posNew[idStringify(id)]].item,                                         // 248
        position,                                                                       // 249
        before);                                                                        // 250
    },                                                                                  // 251
    movedBefore: function (id, before) {                                                // 252
      var prevPosition = posCur[idStringify(id)];                                       // 253
      var position = before ? posCur[idStringify(before)] : lengthCur - 1;              // 254
                                                                                        // 255
      _.each(posCur, function (pos, id) {                                               // 256
        if (pos >= prevPosition && pos <= position)                                     // 257
          posCur[id]--;                                                                 // 258
        else if (pos <= prevPosition && pos >= position)                                // 259
          posCur[id]++;                                                                 // 260
      });                                                                               // 261
                                                                                        // 262
      posCur[idStringify(id)] = position;                                               // 263
                                                                                        // 264
      callbacks.movedTo(                                                                // 265
        id,                                                                             // 266
        seqArray[posNew[idStringify(id)]].item,                                         // 267
        prevPosition,                                                                   // 268
        position,                                                                       // 269
        before);                                                                        // 270
    },                                                                                  // 271
    removed: function (id) {                                                            // 272
      var prevPosition = posCur[idStringify(id)];                                       // 273
                                                                                        // 274
      _.each(posCur, function (pos, id) {                                               // 275
        if (pos >= prevPosition)                                                        // 276
          posCur[id]--;                                                                 // 277
      });                                                                               // 278
                                                                                        // 279
      delete posCur[idStringify(id)];                                                   // 280
      lengthCur--;                                                                      // 281
                                                                                        // 282
      callbacks.removedAt(                                                              // 283
        id,                                                                             // 284
        lastSeqArray[posOld[idStringify(id)]].item,                                     // 285
        prevPosition);                                                                  // 286
    }                                                                                   // 287
  });                                                                                   // 288
                                                                                        // 289
  _.each(posNew, function (pos, idString) {                                             // 290
    var id = idParse(idString);                                                         // 291
    if (_.has(posOld, idString)) {                                                      // 292
      // specifically for primitive types, compare equality before                      // 293
      // firing the 'changedAt' callback. otherwise, always fire it                     // 294
      // because doing a deep EJSON comparison is not guaranteed to                     // 295
      // work (an array can contain arbitrary objects, and 'transform'                  // 296
      // can be used on cursors). also, deep diffing is not                             // 297
      // necessarily the most efficient (if only a specific subfield                    // 298
      // of the object is later accessed).                                              // 299
      var newItem = seqArray[pos].item;                                                 // 300
      var oldItem = lastSeqArray[posOld[idString]].item;                                // 301
                                                                                        // 302
      if (typeof newItem === 'object' || newItem !== oldItem)                           // 303
          callbacks.changedAt(id, newItem, oldItem, pos);                               // 304
      }                                                                                 // 305
  });                                                                                   // 306
};                                                                                      // 307
                                                                                        // 308
//////////////////////////////////////////////////////////////////////////////////////////

}).call(this);


/* Exports */
if (typeof Package === 'undefined') Package = {};
Package['observe-sequence'] = {
  ObserveSequence: ObserveSequence
};

})();

//# sourceMappingURL=4e05989af52e13ed5032f712022fe58c7ee894ed.map
