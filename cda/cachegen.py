#!/usr/bin/env python2
import os
import sys

basedir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(basedir+"/clang/llvm/tools/clang/bindings/python")
import clang.cindex as ci
ci.Config.set_library_file(basedir+"/clang/build/Release+Asserts/lib/libclang.so")

import pickle
from clang.cindex import CursorKind

import json
from hashlib import sha1

# debug
DEBUG = 0

# cache generated
file_cache = {}
object_cache = {}
xref_cache = {}

# a single index for the runtime of the server
index = ci.Index.create()

def parse_node(node, d, filename, care):
  #print node.location.file
  if node.location.file != None and str(node.location.file) != filename:
    return

  ref = node.referenced
  if type(ref) != type(None):
    usr = ref.get_usr()
    #print "  "*d, node.kind, node.spelling, node.displayname, node.location, node.extent.start.offset, node.extent.end.offset, node.get_usr(), "****", ref.spelling, ref.location, ref.get_usr()
  else:
    usr = None

  if DEBUG == 1:
    print "  "*d, node.kind, node.spelling, node.displayname, node.location, node.location.offset, node.extent.start.offset, node.extent.end.offset, usr

  """
  if DEBUG == 1:
    print "  "*d, node.kind, node.spelling, node.displayname, node.location, node.location.offset, node.extent.start.offset, node.extent.end.offset, usr
  """

  #print dir(node)
  """
  print ref, node.get_usr()
    print ref.location
    for i in deff:
      print i
  """
  
  klass = str(node.kind).split('.')[-1]
  (start, end) = (None, None)
  if node.kind in [CursorKind.STRING_LITERAL, CursorKind.INTEGER_LITERAL, CursorKind.TYPE_REF, CursorKind.TEMPLATE_REF]:
  #if node.kind in [CursorKind.STRING_LITERAL, CursorKind.TYPE_REF, CursorKind.TEMPLATE_REF]:
    start = node.extent.start.offset
    end = node.extent.end.offset
  elif node.kind in [CursorKind.FUNCTION_DECL, CursorKind.FUNCTION_TEMPLATE, CursorKind.VAR_DECL, CursorKind.CLASS_DECL, CursorKind.CXX_METHOD, CursorKind.CLASS_TEMPLATE, CursorKind.PARM_DECL]:
    start = node.location.offset
    end = node.location.offset + len(node.spelling)
  elif node.kind in [CursorKind.MEMBER_REF_EXPR]:
    #print node.location.offset, node.extent.start.offset, node.extent.end.offset
    if node.location.offset != 0:
      start = node.location.offset
    else:
      start = node.extent.start.offset
    end = node.extent.end.offset
    #end = node.location.offset + len(node.displayname)
  elif node.kind in [CursorKind.DECL_REF_EXPR]:
    start = node.location.offset
    end = node.extent.end.offset

  if end != None:
    care.append((start, end, klass, usr))

  if end != None and usr != None and node.location.line > 0:
    newval = filename+"#"+str(node.location.line)
    if node.is_definition():
      # defining the object
      if usr in object_cache:
        object_cache[usr].append(newval)
      else:
        object_cache[usr] = [newval]
    else:
      # xref
      if usr in xref_cache:
        xref_cache[usr].append(newval)
      else:
        xref_cache[usr] = [newval]
      # link here is good

  for child in node.get_children():
    parse_node(child, d+1, filename, care)

def parse_file(filename, args=[]):
  # traversal attack
  tu = index.parse(filename, args=args)

  # bad shit happened
  bad = False
  for m in tu.diagnostics:
    if m.severity >= 3:
      print m
      bad = True
  if bad == True:
    #raise Exception("parsing issue")
    print "parsing issue"

  # extract the things we care about
  care = []
  parse_node(tu.cursor, 0, filename, care)
  care = sorted(care)

  # get file data
  rdat = open(filename).read()

  return (care, rdat)

def parse_files(files, args=[]):
  args.append("-I")
  args.append(basedir+"/clang/build/Release+Asserts/lib/clang/3.4.2/include")
  for fn in files:
    print "CDA: caching",fn
    try:
      file_cache[fn] = parse_file(fn, args)
    except Exception as e:
      print "CDA: error on",fn,":",e
  dat = (object_cache, file_cache, xref_cache)
  return dat

