#!/usr/bin/env python2.7
import os
import sys
import cgi
from flask import Flask,redirect,request,Blueprint

app = Blueprint('static',__name__)
# make sure we can get the socketio stuff here

@app.route("/blah")
def blah():
  return "blah"

