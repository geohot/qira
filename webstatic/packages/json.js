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

/* Package-scope variables */
var JSON;

(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                        //
// packages/json/json_native.js                                                                           //
//                                                                                                        //
////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                          //
// Do we already have a global JSON object? Export it as our JSON object.                                 // 1
if (window.JSON)                                                                                          // 2
  JSON = window.JSON;                                                                                     // 3
                                                                                                          // 4
////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                        //
// packages/json/json2.js                                                                                 //
//                                                                                                        //
////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                          //
/*                                                                                                        // 1
    json2.js                                                                                              // 2
    2012-10-08                                                                                            // 3
                                                                                                          // 4
    Public Domain.                                                                                        // 5
                                                                                                          // 6
    NO WARRANTY EXPRESSED OR IMPLIED. USE AT YOUR OWN RISK.                                               // 7
                                                                                                          // 8
    See http://www.JSON.org/js.html                                                                       // 9
                                                                                                          // 10
                                                                                                          // 11
    This code should be minified before deployment.                                                       // 12
    See http://javascript.crockford.com/jsmin.html                                                        // 13
                                                                                                          // 14
    USE YOUR OWN COPY. IT IS EXTREMELY UNWISE TO LOAD CODE FROM SERVERS YOU DO                            // 15
    NOT CONTROL.                                                                                          // 16
                                                                                                          // 17
                                                                                                          // 18
    This file creates a global JSON object containing two methods: stringify                              // 19
    and parse.                                                                                            // 20
                                                                                                          // 21
        JSON.stringify(value, replacer, space)                                                            // 22
            value       any JavaScript value, usually an object or array.                                 // 23
                                                                                                          // 24
            replacer    an optional parameter that determines how object                                  // 25
                        values are stringified for objects. It can be a                                   // 26
                        function or an array of strings.                                                  // 27
                                                                                                          // 28
            space       an optional parameter that specifies the indentation                              // 29
                        of nested structures. If it is omitted, the text will                             // 30
                        be packed without extra whitespace. If it is a number,                            // 31
                        it will specify the number of spaces to indent at each                            // 32
                        level. If it is a string (such as '\t' or '&nbsp;'),                              // 33
                        it contains the characters used to indent at each level.                          // 34
                                                                                                          // 35
            This method produces a JSON text from a JavaScript value.                                     // 36
                                                                                                          // 37
            When an object value is found, if the object contains a toJSON                                // 38
            method, its toJSON method will be called and the result will be                               // 39
            stringified. A toJSON method does not serialize: it returns the                               // 40
            value represented by the name/value pair that should be serialized,                           // 41
            or undefined if nothing should be serialized. The toJSON method                               // 42
            will be passed the key associated with the value, and this will be                            // 43
            bound to the value                                                                            // 44
                                                                                                          // 45
            For example, this would serialize Dates as ISO strings.                                       // 46
                                                                                                          // 47
                Date.prototype.toJSON = function (key) {                                                  // 48
                    function f(n) {                                                                       // 49
                        // Format integers to have at least two digits.                                   // 50
                        return n < 10 ? '0' + n : n;                                                      // 51
                    }                                                                                     // 52
                                                                                                          // 53
                    return this.getUTCFullYear()   + '-' +                                                // 54
                         f(this.getUTCMonth() + 1) + '-' +                                                // 55
                         f(this.getUTCDate())      + 'T' +                                                // 56
                         f(this.getUTCHours())     + ':' +                                                // 57
                         f(this.getUTCMinutes())   + ':' +                                                // 58
                         f(this.getUTCSeconds())   + 'Z';                                                 // 59
                };                                                                                        // 60
                                                                                                          // 61
            You can provide an optional replacer method. It will be passed the                            // 62
            key and value of each member, with this bound to the containing                               // 63
            object. The value that is returned from your method will be                                   // 64
            serialized. If your method returns undefined, then the member will                            // 65
            be excluded from the serialization.                                                           // 66
                                                                                                          // 67
            If the replacer parameter is an array of strings, then it will be                             // 68
            used to select the members to be serialized. It filters the results                           // 69
            such that only members with keys listed in the replacer array are                             // 70
            stringified.                                                                                  // 71
                                                                                                          // 72
            Values that do not have JSON representations, such as undefined or                            // 73
            functions, will not be serialized. Such values in objects will be                             // 74
            dropped; in arrays they will be replaced with null. You can use                               // 75
            a replacer function to replace those with JSON values.                                        // 76
            JSON.stringify(undefined) returns undefined.                                                  // 77
                                                                                                          // 78
            The optional space parameter produces a stringification of the                                // 79
            value that is filled with line breaks and indentation to make it                              // 80
            easier to read.                                                                               // 81
                                                                                                          // 82
            If the space parameter is a non-empty string, then that string will                           // 83
            be used for indentation. If the space parameter is a number, then                             // 84
            the indentation will be that many spaces.                                                     // 85
                                                                                                          // 86
            Example:                                                                                      // 87
                                                                                                          // 88
            text = JSON.stringify(['e', {pluribus: 'unum'}]);                                             // 89
            // text is '["e",{"pluribus":"unum"}]'                                                        // 90
                                                                                                          // 91
                                                                                                          // 92
            text = JSON.stringify(['e', {pluribus: 'unum'}], null, '\t');                                 // 93
            // text is '[\n\t"e",\n\t{\n\t\t"pluribus": "unum"\n\t}\n]'                                   // 94
                                                                                                          // 95
            text = JSON.stringify([new Date()], function (key, value) {                                   // 96
                return this[key] instanceof Date ?                                                        // 97
                    'Date(' + this[key] + ')' : value;                                                    // 98
            });                                                                                           // 99
            // text is '["Date(---current time---)"]'                                                     // 100
                                                                                                          // 101
                                                                                                          // 102
        JSON.parse(text, reviver)                                                                         // 103
            This method parses a JSON text to produce an object or array.                                 // 104
            It can throw a SyntaxError exception.                                                         // 105
                                                                                                          // 106
            The optional reviver parameter is a function that can filter and                              // 107
            transform the results. It receives each of the keys and values,                               // 108
            and its return value is used instead of the original value.                                   // 109
            If it returns what it received, then the structure is not modified.                           // 110
            If it returns undefined then the member is deleted.                                           // 111
                                                                                                          // 112
            Example:                                                                                      // 113
                                                                                                          // 114
            // Parse the text. Values that look like ISO date strings will                                // 115
            // be converted to Date objects.                                                              // 116
                                                                                                          // 117
            myData = JSON.parse(text, function (key, value) {                                             // 118
                var a;                                                                                    // 119
                if (typeof value === 'string') {                                                          // 120
                    a =                                                                                   // 121
/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2}(?:\.\d*)?)Z$/.exec(value);                               // 122
                    if (a) {                                                                              // 123
                        return new Date(Date.UTC(+a[1], +a[2] - 1, +a[3], +a[4],                          // 124
                            +a[5], +a[6]));                                                               // 125
                    }                                                                                     // 126
                }                                                                                         // 127
                return value;                                                                             // 128
            });                                                                                           // 129
                                                                                                          // 130
            myData = JSON.parse('["Date(09/09/2001)"]', function (key, value) {                           // 131
                var d;                                                                                    // 132
                if (typeof value === 'string' &&                                                          // 133
                        value.slice(0, 5) === 'Date(' &&                                                  // 134
                        value.slice(-1) === ')') {                                                        // 135
                    d = new Date(value.slice(5, -1));                                                     // 136
                    if (d) {                                                                              // 137
                        return d;                                                                         // 138
                    }                                                                                     // 139
                }                                                                                         // 140
                return value;                                                                             // 141
            });                                                                                           // 142
                                                                                                          // 143
                                                                                                          // 144
    This is a reference implementation. You are free to copy, modify, or                                  // 145
    redistribute.                                                                                         // 146
*/                                                                                                        // 147
                                                                                                          // 148
/*jslint evil: true, regexp: true */                                                                      // 149
                                                                                                          // 150
/*members "", "\b", "\t", "\n", "\f", "\r", "\"", JSON, "\\", apply,                                      // 151
    call, charCodeAt, getUTCDate, getUTCFullYear, getUTCHours,                                            // 152
    getUTCMinutes, getUTCMonth, getUTCSeconds, hasOwnProperty, join,                                      // 153
    lastIndex, length, parse, prototype, push, replace, slice, stringify,                                 // 154
    test, toJSON, toString, valueOf                                                                       // 155
*/                                                                                                        // 156
                                                                                                          // 157
                                                                                                          // 158
// Create a JSON object only if one does not already exist. We create the                                 // 159
// methods in a closure to avoid creating global variables.                                               // 160
                                                                                                          // 161
if (typeof JSON !== 'object') {                                                                           // 162
    JSON = {};                                                                                            // 163
}                                                                                                         // 164
                                                                                                          // 165
(function () {                                                                                            // 166
    'use strict';                                                                                         // 167
                                                                                                          // 168
    function f(n) {                                                                                       // 169
        // Format integers to have at least two digits.                                                   // 170
        return n < 10 ? '0' + n : n;                                                                      // 171
    }                                                                                                     // 172
                                                                                                          // 173
    if (typeof Date.prototype.toJSON !== 'function') {                                                    // 174
                                                                                                          // 175
        Date.prototype.toJSON = function (key) {                                                          // 176
                                                                                                          // 177
            return isFinite(this.valueOf())                                                               // 178
                ? this.getUTCFullYear()     + '-' +                                                       // 179
                    f(this.getUTCMonth() + 1) + '-' +                                                     // 180
                    f(this.getUTCDate())      + 'T' +                                                     // 181
                    f(this.getUTCHours())     + ':' +                                                     // 182
                    f(this.getUTCMinutes())   + ':' +                                                     // 183
                    f(this.getUTCSeconds())   + 'Z'                                                       // 184
                : null;                                                                                   // 185
        };                                                                                                // 186
                                                                                                          // 187
        String.prototype.toJSON      =                                                                    // 188
            Number.prototype.toJSON  =                                                                    // 189
            Boolean.prototype.toJSON = function (key) {                                                   // 190
                return this.valueOf();                                                                    // 191
            };                                                                                            // 192
    }                                                                                                     // 193
                                                                                                          // 194
    var cx = /[\u0000\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g,
        escapable = /[\\\"\x00-\x1f\x7f-\x9f\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g,
        gap,                                                                                              // 197
        indent,                                                                                           // 198
        meta = {    // table of character substitutions                                                   // 199
            '\b': '\\b',                                                                                  // 200
            '\t': '\\t',                                                                                  // 201
            '\n': '\\n',                                                                                  // 202
            '\f': '\\f',                                                                                  // 203
            '\r': '\\r',                                                                                  // 204
            '"' : '\\"',                                                                                  // 205
            '\\': '\\\\'                                                                                  // 206
        },                                                                                                // 207
        rep;                                                                                              // 208
                                                                                                          // 209
                                                                                                          // 210
    function quote(string) {                                                                              // 211
                                                                                                          // 212
// If the string contains no control characters, no quote characters, and no                              // 213
// backslash characters, then we can safely slap some quotes around it.                                   // 214
// Otherwise we must also replace the offending characters with safe escape                               // 215
// sequences.                                                                                             // 216
                                                                                                          // 217
        escapable.lastIndex = 0;                                                                          // 218
        return escapable.test(string) ? '"' + string.replace(escapable, function (a) {                    // 219
            var c = meta[a];                                                                              // 220
            return typeof c === 'string'                                                                  // 221
                ? c                                                                                       // 222
                : '\\u' + ('0000' + a.charCodeAt(0).toString(16)).slice(-4);                              // 223
        }) + '"' : '"' + string + '"';                                                                    // 224
    }                                                                                                     // 225
                                                                                                          // 226
                                                                                                          // 227
    function str(key, holder) {                                                                           // 228
                                                                                                          // 229
// Produce a string from holder[key].                                                                     // 230
                                                                                                          // 231
        var i,          // The loop counter.                                                              // 232
            k,          // The member key.                                                                // 233
            v,          // The member value.                                                              // 234
            length,                                                                                       // 235
            mind = gap,                                                                                   // 236
            partial,                                                                                      // 237
            value = holder[key];                                                                          // 238
                                                                                                          // 239
// If the value has a toJSON method, call it to obtain a replacement value.                               // 240
                                                                                                          // 241
        if (value && typeof value === 'object' &&                                                         // 242
                typeof value.toJSON === 'function') {                                                     // 243
            value = value.toJSON(key);                                                                    // 244
        }                                                                                                 // 245
                                                                                                          // 246
// If we were called with a replacer function, then call the replacer to                                  // 247
// obtain a replacement value.                                                                            // 248
                                                                                                          // 249
        if (typeof rep === 'function') {                                                                  // 250
            value = rep.call(holder, key, value);                                                         // 251
        }                                                                                                 // 252
                                                                                                          // 253
// What happens next depends on the value's type.                                                         // 254
                                                                                                          // 255
        switch (typeof value) {                                                                           // 256
        case 'string':                                                                                    // 257
            return quote(value);                                                                          // 258
                                                                                                          // 259
        case 'number':                                                                                    // 260
                                                                                                          // 261
// JSON numbers must be finite. Encode non-finite numbers as null.                                        // 262
                                                                                                          // 263
            return isFinite(value) ? String(value) : 'null';                                              // 264
                                                                                                          // 265
        case 'boolean':                                                                                   // 266
        case 'null':                                                                                      // 267
                                                                                                          // 268
// If the value is a boolean or null, convert it to a string. Note:                                       // 269
// typeof null does not produce 'null'. The case is included here in                                      // 270
// the remote chance that this gets fixed someday.                                                        // 271
                                                                                                          // 272
            return String(value);                                                                         // 273
                                                                                                          // 274
// If the type is 'object', we might be dealing with an object or an array or                             // 275
// null.                                                                                                  // 276
                                                                                                          // 277
        case 'object':                                                                                    // 278
                                                                                                          // 279
// Due to a specification blunder in ECMAScript, typeof null is 'object',                                 // 280
// so watch out for that case.                                                                            // 281
                                                                                                          // 282
            if (!value) {                                                                                 // 283
                return 'null';                                                                            // 284
            }                                                                                             // 285
                                                                                                          // 286
// Make an array to hold the partial results of stringifying this object value.                           // 287
                                                                                                          // 288
            gap += indent;                                                                                // 289
            partial = [];                                                                                 // 290
                                                                                                          // 291
// Is the value an array?                                                                                 // 292
                                                                                                          // 293
            if (Object.prototype.toString.apply(value) === '[object Array]') {                            // 294
                                                                                                          // 295
// The value is an array. Stringify every element. Use null as a placeholder                              // 296
// for non-JSON values.                                                                                   // 297
                                                                                                          // 298
                length = value.length;                                                                    // 299
                for (i = 0; i < length; i += 1) {                                                         // 300
                    partial[i] = str(i, value) || 'null';                                                 // 301
                }                                                                                         // 302
                                                                                                          // 303
// Join all of the elements together, separated with commas, and wrap them in                             // 304
// brackets.                                                                                              // 305
                                                                                                          // 306
                v = partial.length === 0                                                                  // 307
                    ? '[]'                                                                                // 308
                    : gap                                                                                 // 309
                    ? '[\n' + gap + partial.join(',\n' + gap) + '\n' + mind + ']'                         // 310
                    : '[' + partial.join(',') + ']';                                                      // 311
                gap = mind;                                                                               // 312
                return v;                                                                                 // 313
            }                                                                                             // 314
                                                                                                          // 315
// If the replacer is an array, use it to select the members to be stringified.                           // 316
                                                                                                          // 317
            if (rep && typeof rep === 'object') {                                                         // 318
                length = rep.length;                                                                      // 319
                for (i = 0; i < length; i += 1) {                                                         // 320
                    if (typeof rep[i] === 'string') {                                                     // 321
                        k = rep[i];                                                                       // 322
                        v = str(k, value);                                                                // 323
                        if (v) {                                                                          // 324
                            partial.push(quote(k) + (gap ? ': ' : ':') + v);                              // 325
                        }                                                                                 // 326
                    }                                                                                     // 327
                }                                                                                         // 328
            } else {                                                                                      // 329
                                                                                                          // 330
// Otherwise, iterate through all of the keys in the object.                                              // 331
                                                                                                          // 332
                for (k in value) {                                                                        // 333
                    if (Object.prototype.hasOwnProperty.call(value, k)) {                                 // 334
                        v = str(k, value);                                                                // 335
                        if (v) {                                                                          // 336
                            partial.push(quote(k) + (gap ? ': ' : ':') + v);                              // 337
                        }                                                                                 // 338
                    }                                                                                     // 339
                }                                                                                         // 340
            }                                                                                             // 341
                                                                                                          // 342
// Join all of the member texts together, separated with commas,                                          // 343
// and wrap them in braces.                                                                               // 344
                                                                                                          // 345
            v = partial.length === 0                                                                      // 346
                ? '{}'                                                                                    // 347
                : gap                                                                                     // 348
                ? '{\n' + gap + partial.join(',\n' + gap) + '\n' + mind + '}'                             // 349
                : '{' + partial.join(',') + '}';                                                          // 350
            gap = mind;                                                                                   // 351
            return v;                                                                                     // 352
        }                                                                                                 // 353
    }                                                                                                     // 354
                                                                                                          // 355
// If the JSON object does not yet have a stringify method, give it one.                                  // 356
                                                                                                          // 357
    if (typeof JSON.stringify !== 'function') {                                                           // 358
        JSON.stringify = function (value, replacer, space) {                                              // 359
                                                                                                          // 360
// The stringify method takes a value and an optional replacer, and an optional                           // 361
// space parameter, and returns a JSON text. The replacer can be a function                               // 362
// that can replace values, or an array of strings that will select the keys.                             // 363
// A default replacer method can be provided. Use of the space parameter can                              // 364
// produce text that is more easily readable.                                                             // 365
                                                                                                          // 366
            var i;                                                                                        // 367
            gap = '';                                                                                     // 368
            indent = '';                                                                                  // 369
                                                                                                          // 370
// If the space parameter is a number, make an indent string containing that                              // 371
// many spaces.                                                                                           // 372
                                                                                                          // 373
            if (typeof space === 'number') {                                                              // 374
                for (i = 0; i < space; i += 1) {                                                          // 375
                    indent += ' ';                                                                        // 376
                }                                                                                         // 377
                                                                                                          // 378
// If the space parameter is a string, it will be used as the indent string.                              // 379
                                                                                                          // 380
            } else if (typeof space === 'string') {                                                       // 381
                indent = space;                                                                           // 382
            }                                                                                             // 383
                                                                                                          // 384
// If there is a replacer, it must be a function or an array.                                             // 385
// Otherwise, throw an error.                                                                             // 386
                                                                                                          // 387
            rep = replacer;                                                                               // 388
            if (replacer && typeof replacer !== 'function' &&                                             // 389
                    (typeof replacer !== 'object' ||                                                      // 390
                    typeof replacer.length !== 'number')) {                                               // 391
                throw new Error('JSON.stringify');                                                        // 392
            }                                                                                             // 393
                                                                                                          // 394
// Make a fake root object containing our value under the key of ''.                                      // 395
// Return the result of stringifying the value.                                                           // 396
                                                                                                          // 397
            return str('', {'': value});                                                                  // 398
        };                                                                                                // 399
    }                                                                                                     // 400
                                                                                                          // 401
                                                                                                          // 402
// If the JSON object does not yet have a parse method, give it one.                                      // 403
                                                                                                          // 404
    if (typeof JSON.parse !== 'function') {                                                               // 405
        JSON.parse = function (text, reviver) {                                                           // 406
                                                                                                          // 407
// The parse method takes a text and an optional reviver function, and returns                            // 408
// a JavaScript value if the text is a valid JSON text.                                                   // 409
                                                                                                          // 410
            var j;                                                                                        // 411
                                                                                                          // 412
            function walk(holder, key) {                                                                  // 413
                                                                                                          // 414
// The walk method is used to recursively walk the resulting structure so                                 // 415
// that modifications can be made.                                                                        // 416
                                                                                                          // 417
                var k, v, value = holder[key];                                                            // 418
                if (value && typeof value === 'object') {                                                 // 419
                    for (k in value) {                                                                    // 420
                        if (Object.prototype.hasOwnProperty.call(value, k)) {                             // 421
                            v = walk(value, k);                                                           // 422
                            if (v !== undefined) {                                                        // 423
                                value[k] = v;                                                             // 424
                            } else {                                                                      // 425
                                delete value[k];                                                          // 426
                            }                                                                             // 427
                        }                                                                                 // 428
                    }                                                                                     // 429
                }                                                                                         // 430
                return reviver.call(holder, key, value);                                                  // 431
            }                                                                                             // 432
                                                                                                          // 433
                                                                                                          // 434
// Parsing happens in four stages. In the first stage, we replace certain                                 // 435
// Unicode characters with escape sequences. JavaScript handles many characters                           // 436
// incorrectly, either silently deleting them, or treating them as line endings.                          // 437
                                                                                                          // 438
            text = String(text);                                                                          // 439
            cx.lastIndex = 0;                                                                             // 440
            if (cx.test(text)) {                                                                          // 441
                text = text.replace(cx, function (a) {                                                    // 442
                    return '\\u' +                                                                        // 443
                        ('0000' + a.charCodeAt(0).toString(16)).slice(-4);                                // 444
                });                                                                                       // 445
            }                                                                                             // 446
                                                                                                          // 447
// In the second stage, we run the text against regular expressions that look                             // 448
// for non-JSON patterns. We are especially concerned with '()' and 'new'                                 // 449
// because they can cause invocation, and '=' because it can cause mutation.                              // 450
// But just to be safe, we want to reject all unexpected forms.                                           // 451
                                                                                                          // 452
// We split the second stage into 4 regexp operations in order to work around                             // 453
// crippling inefficiencies in IE's and Safari's regexp engines. First we                                 // 454
// replace the JSON backslash pairs with '@' (a non-JSON character). Second, we                           // 455
// replace all simple value tokens with ']' characters. Third, we delete all                              // 456
// open brackets that follow a colon or comma or that begin the text. Finally,                            // 457
// we look to see that the remaining characters are only whitespace or ']' or                             // 458
// ',' or ':' or '{' or '}'. If that is so, then the text is safe for eval.                               // 459
                                                                                                          // 460
            if (/^[\],:{}\s]*$/                                                                           // 461
                    .test(text.replace(/\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4})/g, '@')                        // 462
                        .replace(/"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g, ']') // 463
                        .replace(/(?:^|:|,)(?:\s*\[)+/g, ''))) {                                          // 464
                                                                                                          // 465
// In the third stage we use the eval function to compile the text into a                                 // 466
// JavaScript structure. The '{' operator is subject to a syntactic ambiguity                             // 467
// in JavaScript: it can begin a block or an object literal. We wrap the text                             // 468
// in parens to eliminate the ambiguity.                                                                  // 469
                                                                                                          // 470
                j = eval('(' + text + ')');                                                               // 471
                                                                                                          // 472
// In the optional fourth stage, we recursively walk the new structure, passing                           // 473
// each name/value pair to a reviver function for possible transformation.                                // 474
                                                                                                          // 475
                return typeof reviver === 'function'                                                      // 476
                    ? walk({'': j}, '')                                                                   // 477
                    : j;                                                                                  // 478
            }                                                                                             // 479
                                                                                                          // 480
// If the text is not JSON parseable, then a SyntaxError is thrown.                                       // 481
                                                                                                          // 482
            throw new SyntaxError('JSON.parse');                                                          // 483
        };                                                                                                // 484
    }                                                                                                     // 485
}());                                                                                                     // 486
                                                                                                          // 487
////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);


/* Exports */
if (typeof Package === 'undefined') Package = {};
Package.json = {
  JSON: JSON
};

})();

//# sourceMappingURL=e22856eae714c681199eabc5c0710b904b125554.map
