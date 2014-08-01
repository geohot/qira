#!/usr/bin/env python
import os
import sys
import cgi
from flask import Flask,redirect,request,Blueprint
from html import XHTML

app = Blueprint('cda',__name__)

# escape on the real
def escape(s, crap=False):
  return s.replace("<", "&lt;").replace(">", "&gt;").replace(" ", "&nbsp;").replace("\n", "<br/>").replace("\t", "&nbsp;"*4).replace("\x00", " ")
cgi.escape = escape

@app.route("/list")
def list():
  h = XHTML().html
  for f in sorted(file_cache.keys()):
    h.body.div.a(f, href="#"+f+",0,")
  return str(h)

# only path that should be here now
@app.route("/cda")
def home():
  # generate html
  h = XHTML().html
  h.head.link(rel="stylesheet", href="/cdastatic/cda.css")
  h.head.script(src="/cdastatic/socket.io.min.js")
  h.head.script(src="/cdastatic/jquery-2.1.0.js")
  h.head.script(src="/cdastatic/jquery.scrollTo.min.js")
  h.head.script(src="/cdastatic/cda.js?"+os.urandom(16).encode("hex"))
  body = h.body
  prog = body.div(id="program")
  xrefs = body.div(id="xrefs")

  return str(h)

@app.route("/x/<b64xref>")
def display_xref(b64xref):
  xref = b64xref.decode("base64")
  h = XHTML().html
  h.head.link(rel="stylesheet", href="/cdastatic/cda.css")
  body = h.body(klass="xref")
  body.div.div(xref, klass="xrefstitle")
  if xref in xref_cache:
    for obj in xref_cache[xref]:
      linkobj = obj.replace("#",",")+","+b64xref
      body.div.a(obj, onclick="location.replace('#"+linkobj+"')", klass="filelink")
  return str(body)

@app.route("/f")
def display_file():
  path = request.query_string
  if path not in file_cache:
    return "file "+str(path)+" not found"
  # generate the HTML
  h = XHTML().html
  body = h.body
  body.div(path, id='filename')
  #body.iframe(id='bottomframe')

  # get parsed file
  (care, rdat) = file_cache[path]

  # add line numbers
  lc = len(rdat.split("\n"))
  ln = body.div(id="ln")
  for linenum in range(lc):
    ln.span("%5d \n" % (linenum+1), id="l"+str(linenum+1), onclick='go_to_line('+str(linenum+1)+')')

  # add the code
  #print object_cache
  p = body.div(id="code")
  last = 0
  for (start, end, klass, usr) in care:
    if last > start:
      # this is not the proper fix
      #print "OMG ISSUE ",last,start,klass,usr
      continue
    p.span(rdat[last:start])
    if usr != None:
      if usr in object_cache:
        #p.span(klass=klass, usr=usr).a(rdat[start:end], href="/f/"+object_cache[usr][0])
        #if usr in xref_cache:
          #p.span(rdat[start:end], klass=klass+"\x00link", usr=usr, targets='\x00'.join(object_cache[usr]), xrefs='\x00'.join(xref_cache[usr]))
        #else:
        p.span(rdat[start:end], klass=klass+"\x00link", name=usr, targets='\x00'.join(object_cache[usr]))
      else:
        p.span(rdat[start:end], klass=klass, name=usr)
    else:
      p.span(rdat[start:end], klass=klass)
    last = end
  p.span(rdat[last:])

  return str(body)

def set_cache(cache):
  global object_cache, file_cache, xref_cache
  (object_cache, file_cache, xref_cache) = cache
  print "CDA: read",len(file_cache),"files",len(object_cache),"objects",len(xref_cache),"xrefs"

