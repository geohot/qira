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
var Log;

(function () {

/////////////////////////////////////////////////////////////////////////////////////////
//                                                                                     //
// packages/logging/logging.js                                                         //
//                                                                                     //
/////////////////////////////////////////////////////////////////////////////////////////
                                                                                       //
Log = function () {                                                                    // 1
  return Log.info.apply(this, arguments);                                              // 2
};                                                                                     // 3
                                                                                       // 4
/// FOR TESTING                                                                        // 5
var intercept = 0;                                                                     // 6
var interceptedLines = [];                                                             // 7
var suppress = 0;                                                                      // 8
                                                                                       // 9
// Intercept the next 'count' calls to a Log function. The actual                      // 10
// lines printed to the console can be cleared and read by calling                     // 11
// Log._intercepted().                                                                 // 12
Log._intercept = function (count) {                                                    // 13
  intercept += count;                                                                  // 14
};                                                                                     // 15
                                                                                       // 16
// Suppress the next 'count' calls to a Log function. Use this to stop                 // 17
// tests from spamming the console, especially with red errors that                    // 18
// might look like a failing test.                                                     // 19
Log._suppress = function (count) {                                                     // 20
  suppress += count;                                                                   // 21
};                                                                                     // 22
                                                                                       // 23
// Returns intercepted lines and resets the intercept counter.                         // 24
Log._intercepted = function () {                                                       // 25
  var lines = interceptedLines;                                                        // 26
  interceptedLines = [];                                                               // 27
  intercept = 0;                                                                       // 28
  return lines;                                                                        // 29
};                                                                                     // 30
                                                                                       // 31
// Either 'json' or 'colored-text'.                                                    // 32
//                                                                                     // 33
// When this is set to 'json', print JSON documents that are parsed by another         // 34
// process ('satellite' or 'meteor run'). This other process should call               // 35
// 'Log.format' for nice output.                                                       // 36
//                                                                                     // 37
// When this is set to 'colored-text', call 'Log.format' before printing.              // 38
// This should be used for logging from within satellite, since there is no            // 39
// other process that will be reading its standard output.                             // 40
Log.outputFormat = 'json';                                                             // 41
                                                                                       // 42
var LEVEL_COLORS = {                                                                   // 43
  debug: 'green',                                                                      // 44
  // leave info as the default color                                                   // 45
  warn: 'magenta',                                                                     // 46
  error: 'red'                                                                         // 47
};                                                                                     // 48
                                                                                       // 49
var META_COLOR = 'blue';                                                               // 50
                                                                                       // 51
// XXX package                                                                         // 52
var RESTRICTED_KEYS = ['time', 'timeInexact', 'level', 'file', 'line',                 // 53
                        'program', 'originApp', 'satellite', 'stderr'];                // 54
                                                                                       // 55
var FORMATTED_KEYS = RESTRICTED_KEYS.concat(['app', 'message']);                       // 56
                                                                                       // 57
var logInBrowser = function (obj) {                                                    // 58
  var str = Log.format(obj);                                                           // 59
                                                                                       // 60
  // XXX Some levels should be probably be sent to the server                          // 61
  var level = obj.level;                                                               // 62
                                                                                       // 63
  if ((typeof console !== 'undefined') && console[level]) {                            // 64
    console[level](str);                                                               // 65
  } else {                                                                             // 66
    // XXX Uses of Meteor._debug should probably be replaced by Log.debug or           // 67
    //     Log.info, and we should have another name for "do your best to              // 68
    //     call call console.log".                                                     // 69
    Meteor._debug(str);                                                                // 70
  }                                                                                    // 71
};                                                                                     // 72
                                                                                       // 73
// @returns {Object: { line: Number, file: String }}                                   // 74
Log._getCallerDetails = function () {                                                  // 75
  var getStack = function () {                                                         // 76
    // We do NOT use Error.prepareStackTrace here (a V8 extension that gets us a       // 77
    // pre-parsed stack) since it's impossible to compose it with the use of           // 78
    // Error.prepareStackTrace used on the server for source maps.                     // 79
    var err = new Error;                                                               // 80
    var stack = err.stack;                                                             // 81
    return stack;                                                                      // 82
  };                                                                                   // 83
                                                                                       // 84
  var stack = getStack();                                                              // 85
                                                                                       // 86
  if (!stack) return {};                                                               // 87
                                                                                       // 88
  var lines = stack.split('\n');                                                       // 89
                                                                                       // 90
  // looking for the first line outside the logging package (or an                     // 91
  // eval if we find that first)                                                       // 92
  var line;                                                                            // 93
  for (var i = 1; i < lines.length; ++i) {                                             // 94
    line = lines[i];                                                                   // 95
    if (line.match(/^\s*at eval \(eval/)) {                                            // 96
      return {file: "eval"};                                                           // 97
    }                                                                                  // 98
                                                                                       // 99
    // XXX probably wants to be / or .js in case no source maps                        // 100
    if (!line.match(/packages\/logging(?:\/|(?::tests)?\.js)/))                        // 101
      break;                                                                           // 102
  }                                                                                    // 103
                                                                                       // 104
  var details = {};                                                                    // 105
                                                                                       // 106
  // The format for FF is 'functionName@filePath:lineNumber'                           // 107
  // The format for V8 is 'functionName (packages/logging/logging.js:81)' or           // 108
  //                      'packages/logging/logging.js:81'                             // 109
  var match = /(?:[@(]| at )([^(]+?):([0-9:]+)(?:\)|$)/.exec(line);                    // 110
  if (!match)                                                                          // 111
    return details;                                                                    // 112
  // in case the matched block here is line:column                                     // 113
  details.line = match[2].split(':')[0];                                               // 114
                                                                                       // 115
  // Possible format: https://foo.bar.com/scripts/file.js?random=foobar                // 116
  // XXX: if you can write the following in better way, please do it                   // 117
  // XXX: what about evals?                                                            // 118
  details.file = match[1].split('/').slice(-1)[0].split('?')[0];                       // 119
                                                                                       // 120
  return details;                                                                      // 121
};                                                                                     // 122
                                                                                       // 123
_.each(['debug', 'info', 'warn', 'error'], function (level) {                          // 124
  // @param arg {String|Object}                                                        // 125
  Log[level] = function (arg) {                                                        // 126
    if (suppress) {                                                                    // 127
      suppress--;                                                                      // 128
      return;                                                                          // 129
    }                                                                                  // 130
                                                                                       // 131
    var intercepted = false;                                                           // 132
    if (intercept) {                                                                   // 133
      intercept--;                                                                     // 134
      intercepted = true;                                                              // 135
    }                                                                                  // 136
                                                                                       // 137
    var obj = (_.isObject(arg) && !_.isRegExp(arg) && !_.isDate(arg) ) ?               // 138
              arg : {message: new String(arg).toString() };                            // 139
                                                                                       // 140
    _.each(RESTRICTED_KEYS, function (key) {                                           // 141
      if (obj[key])                                                                    // 142
        throw new Error("Can't set '" + key + "' in log message");                     // 143
    });                                                                                // 144
                                                                                       // 145
    if (_.has(obj, 'message') && !_.isString(obj.message))                             // 146
      throw new Error("The 'message' field in log objects must be a string");          // 147
    if (!obj.omitCallerDetails)                                                        // 148
      obj = _.extend(Log._getCallerDetails(), obj);                                    // 149
    obj.time = new Date();                                                             // 150
    obj.level = level;                                                                 // 151
                                                                                       // 152
    // XXX allow you to enable 'debug', probably per-package                           // 153
    if (level === 'debug')                                                             // 154
      return;                                                                          // 155
                                                                                       // 156
    if (intercepted) {                                                                 // 157
      interceptedLines.push(EJSON.stringify(obj));                                     // 158
    } else if (Meteor.isServer) {                                                      // 159
      if (Log.outputFormat === 'colored-text') {                                       // 160
        console.log(Log.format(obj, {color: true}));                                   // 161
      } else if (Log.outputFormat === 'json') {                                        // 162
        console.log(EJSON.stringify(obj));                                             // 163
      } else {                                                                         // 164
        throw new Error("Unknown logging output format: " + Log.outputFormat);         // 165
      }                                                                                // 166
    } else {                                                                           // 167
      logInBrowser(obj);                                                               // 168
    }                                                                                  // 169
  };                                                                                   // 170
});                                                                                    // 171
                                                                                       // 172
// tries to parse line as EJSON. returns object if parse is successful, or null if not // 173
Log.parse = function (line) {                                                          // 174
  var obj = null;                                                                      // 175
  if (line && line.charAt(0) === '{') { // might be json generated from calling 'Log'  // 176
    try { obj = EJSON.parse(line); } catch (e) {}                                      // 177
  }                                                                                    // 178
                                                                                       // 179
  // XXX should probably check fields other than 'time'                                // 180
  if (obj && obj.time && (obj.time instanceof Date))                                   // 181
    return obj;                                                                        // 182
  else                                                                                 // 183
    return null;                                                                       // 184
};                                                                                     // 185
                                                                                       // 186
// formats a log object into colored human and machine-readable text                   // 187
Log.format = function (obj, options) {                                                 // 188
  obj = EJSON.clone(obj); // don't mutate the argument                                 // 189
  options = options || {};                                                             // 190
                                                                                       // 191
  var time = obj.time;                                                                 // 192
  if (!(time instanceof Date))                                                         // 193
    throw new Error("'time' must be a Date object");                                   // 194
  var timeInexact = obj.timeInexact;                                                   // 195
                                                                                       // 196
  // store fields that are in FORMATTED_KEYS since we strip them                       // 197
  var level = obj.level || 'info';                                                     // 198
  var file = obj.file;                                                                 // 199
  var lineNumber = obj.line;                                                           // 200
  var appName = obj.app || '';                                                         // 201
  var originApp = obj.originApp;                                                       // 202
  var message = obj.message || '';                                                     // 203
  var program = obj.program || '';                                                     // 204
  var satellite = obj.satellite;                                                       // 205
  var stderr = obj.stderr || '';                                                       // 206
                                                                                       // 207
  _.each(FORMATTED_KEYS, function(key) {                                               // 208
    delete obj[key];                                                                   // 209
  });                                                                                  // 210
                                                                                       // 211
  if (!_.isEmpty(obj)) {                                                               // 212
    if (message) message += " ";                                                       // 213
    message += EJSON.stringify(obj);                                                   // 214
  }                                                                                    // 215
                                                                                       // 216
  var pad2 = function(n) { return n < 10 ? '0' + n : n.toString(); };                  // 217
  var pad3 = function(n) { return n < 100 ? '0' + pad2(n) : n.toString(); };           // 218
                                                                                       // 219
  var dateStamp = time.getFullYear().toString() +                                      // 220
    pad2(time.getMonth() + 1 /*0-based*/) +                                            // 221
    pad2(time.getDate());                                                              // 222
  var timeStamp = pad2(time.getHours()) +                                              // 223
        ':' +                                                                          // 224
        pad2(time.getMinutes()) +                                                      // 225
        ':' +                                                                          // 226
        pad2(time.getSeconds()) +                                                      // 227
        '.' +                                                                          // 228
        pad3(time.getMilliseconds());                                                  // 229
                                                                                       // 230
  // eg in San Francisco in June this will be '(-7)'                                   // 231
  var utcOffsetStr = '(' + (-(new Date().getTimezoneOffset() / 60)) + ')';             // 232
                                                                                       // 233
  var appInfo = '';                                                                    // 234
  if (appName) appInfo += appName;                                                     // 235
  if (originApp && originApp !== appName) appInfo += ' via ' + originApp;              // 236
  if (appInfo) appInfo = '[' + appInfo + '] ';                                         // 237
                                                                                       // 238
  var sourceInfo = (file && lineNumber) ?                                              // 239
      ['(', (program ? program + ':' : ''), file, ':', lineNumber, ') '].join('')      // 240
      : '';                                                                            // 241
                                                                                       // 242
  if (satellite)                                                                       // 243
    sourceInfo += ['[', satellite, ']'].join('');                                      // 244
                                                                                       // 245
  var stderrIndicator = stderr ? '(STDERR) ' : '';                                     // 246
                                                                                       // 247
  var metaPrefix = [                                                                   // 248
    level.charAt(0).toUpperCase(),                                                     // 249
    dateStamp,                                                                         // 250
    '-',                                                                               // 251
    timeStamp,                                                                         // 252
    utcOffsetStr,                                                                      // 253
    timeInexact ? '? ' : ' ',                                                          // 254
    appInfo,                                                                           // 255
    sourceInfo,                                                                        // 256
    stderrIndicator].join('');                                                         // 257
                                                                                       // 258
  var prettify = function (line, color) {                                              // 259
    return (options.color && Meteor.isServer && color) ?                               // 260
      Npm.require('cli-color')[color](line) : line;                                    // 261
  };                                                                                   // 262
                                                                                       // 263
  return prettify(metaPrefix, META_COLOR)                                              // 264
    + prettify(message, LEVEL_COLORS[level]);                                          // 265
};                                                                                     // 266
                                                                                       // 267
// Turn a line of text into a loggable object.                                         // 268
// @param line {String}                                                                // 269
// @param override {Object}                                                            // 270
Log.objFromText = function (line, override) {                                          // 271
  var obj = {message: line, level: "info", time: new Date(), timeInexact: true};       // 272
  return _.extend(obj, override);                                                      // 273
};                                                                                     // 274
                                                                                       // 275
/////////////////////////////////////////////////////////////////////////////////////////

}).call(this);


/* Exports */
if (typeof Package === 'undefined') Package = {};
Package.logging = {
  Log: Log
};

})();

//# sourceMappingURL=0de00019cf57ae305903f15baf5dc8e10f973ded.map
