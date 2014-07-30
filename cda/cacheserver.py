#!/usr/bin/env python
import os
import sys
import cgi
from flask import Flask,redirect, request
from html import XHTML
import pickle
app = Flask(__name__, static_folder='static', static_url_path='/static')

# escape on the real
def escape(s, crap=False):
  return s.replace("<", "&lt;").replace(">", "&gt;").replace(" ", "&nbsp;").replace("\n", "<br/>").replace("\t", "&nbsp;"*4).replace("\x00", " ")
cgi.escape = escape

# load the data
print "loading data..."
(object_cache, file_cache, xref_cache) = pickle.load(open(sys.argv[1]))
print "read",len(file_cache),"files",len(object_cache),"objects",len(xref_cache),"xrefs"

@app.route("/")
def home():
  return redirect("/d", code=302)
  #return open("static/index.html").read()

@app.route("/x/<xref>")
def display_xref(xref):
  xref = xref.decode("base64")
  h = XHTML().html
  h.head.link(rel="stylesheet", href="/static/cda.css")
  body = h.body(klass="xref")
  body.div.div(xref, klass="xrefstitle")
  if xref in xref_cache:
    for obj in xref_cache[xref]:
      body.div.a(obj, onclick="window.opener.location = '/f/"+obj+"';", klass="filelink")
  return str(h)

@app.route("/d")
@app.route("/d/<path:path>")
def display_directory(path=""):
  path = path.strip("/")

  # add files
  objs = []
  for f in file_cache:
    lpath = path
    if lpath != "":
      lpath = lpath+"/"
    if f[0:len(path)] == path:
      f = f[len(path):].strip("/")
      if '/' in f:
        f = f.split("/")[0]
        objs.append(("/d/"+lpath+f, f, "dirlink"))
      else:
        objs.append(("/f/"+lpath+f, f, "filelink"))

  # generate html
  h = XHTML().html
  h.head.link(rel="stylesheet", href="/static/cda.css")
  body = h.body
  objs = list(set(objs))
  objs.sort()
  for obj in objs:
    body.div.a(obj[1], href=obj[0], klass=obj[2])
  return str(h)

@app.route("/f/<path:path>")
def display_file(path):
  if path not in file_cache:
    return "file "+str(path)+" not found"
  # generate the HTML
  h = XHTML().html
  h.head.link(rel="stylesheet", href="/static/cda.css")
  h.head.script(src="/static/jquery-2.1.0.js")
  h.head.script(src="/static/jquery.scrollTo-1.4.3.1.js")
  h.head.script(src="/static/cda.js")
  body = h.body

  # get parsed file
  (care, rdat) = file_cache[path]

  # add line numbers
  lc = len(rdat.split("\n"))
  ln = body.div(id="ln")
  for linenum in range(lc):
    ln.span("%5d \n" % (linenum+1), id="l"+str(linenum+1))

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

  return str(h)

def start():
  #app.run(host='127.0.0.1', debug=True, port=5000)
  app.run(host='127.0.0.1', port=5000)

