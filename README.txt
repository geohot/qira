QIRA is an IDA plugin to reverse using QEMU

== Transistion Away From Meteor ==
* Meteor's directory structure is very nice, replicate with 20 lines in python?
* Deps.autorun and Session is nice, but I think this is 30 lines of js with thought
  * I'm fine with listing the session things it depends on
  * Can we cache nothing in the client?
* The whole mongo thing is very slow, and the restarting is dumb
* Mongo can't handle 64-bit unsigned int, but then again, neither can javascript
  * Google for JS bigint solutions
* Consider node as a backend instead of python, code reuse between client and server?

