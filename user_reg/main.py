# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import webapp2
import string
import re
import cgi
import logging
import random
import hashlib
import hmac
from datetime import datetime
from datetime import timedelta


import jinja2
import os

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

SECRET="happygolucky"

# --------------------Datastore Setup-----------------------#

from google.appengine.ext import db

class User(db.Model):
  username=db.StringProperty(required=True)
  passhash=db.StringProperty(required=True)
  email=db.StringProperty()
  createdtime=db.DateTimeProperty(auto_now_add = True)

# --------------------Validation Settings-----------------------#

USER_RE=re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE=re.compile(r"^.{3,20}$")
EMAIL_RE=re.compile(r"^[\S]+@[\S]+\.[\S]+$")

user_error="That's not a valid username."
pass_error="That's not a valid password."
passmatch_error="Your passwords didn't match."
email_error="That's not a valid email."

errormessages=(user_error,pass_error,passmatch_error,email_error)
errorhandles=("user_error","pass_error","passmatch_error","email_error")
errorset=zip(errorhandles,errormessages)
errordict=dict(errorset)

formelements=("username","password","verify","email")

# --------------------Functions-----------------------#
def escape_html(s):
  return cgi.escape(s,quote=True)

def makesalt(n=5):
  return ''.join([random.choice(string.letters) for x in xrange(n)])

def makehash(s, salt):
  return hmac.new(salt,s,hashlib.sha256).hexdigest(),salt

def checkhash(hash, s, salt=""):
  return hmac.new(str(salt), str(s), hashlib.sha256).hexdigest()==str(hash)


# --------------------Handlers-----------------------#

class Handler(webapp2.RequestHandler):
  
  def write(self,*a,**kw):
    self.response.out.write(*a,**kw)

  def render_str(self,template,**params):
    t = jinja_env.get_template(template)
    return t.render(params)

  def render(self,template,**kw):
    self.write(self.render_str(template,**kw))

  def collect_input(self):
    input_orig=[]
    for i in range(0,len(formelements)):
      input_orig.append(self.request.get(formelements[i]))
    for i in range(0,len(input_orig)):
      input_orig[i]=escape_html(input_orig[i])

    return zip(formelements,input_orig)

  def makeusercookie(self,curr_user):
      userID=str(curr_user.key().id())
      cookieHash=makehash(userID,SECRET)
      self.response.set_cookie(
        key="user_ID",
        value="{}|{}".format(userID,cookieHash[0]),
        path="/")
      #self.response.headers.add_header('Set-Cookie','user_ID={}|{}; Path=/'.format(userID,cookieHash[0]))

  def initialize(self,*a,**kw):
    webapp2.RequestHandler.initialize(self,*a,**kw)
    cookie=self.request.cookies.get('user_ID')
    
    if cookie and str(cookie[0])<>'':
      cookie=cookie.split('|')
      if checkhash(cookie[1],cookie[0],SECRET):
        self.user=User.get_by_id(int(cookie[0]))
      else:
        self.user=None
    else:
        self.user=None
         

class MainPage(Handler):
  def get(self):
    self.render('home.html',user=self.user)

class Register(Handler):
    
  def input_validate (self, **kw):
    passmatch=kw['password']==kw['verify']
    emailgood=True

    if kw['email']:
      logging.info("Email was input")
      emailgood=EMAIL_RE.match(kw['email'])

    return zip(errorhandles,(USER_RE.match(kw['username']),PASS_RE.match(kw['password']),passmatch,emailgood))

  def get(self):
    self.render('form_signup.html')

  def post(self):
    formset=self.collect_input()
    formset_lookup=dict(formset)

    validation_response=self.input_validate(**formset_lookup)
    errorlist=[]

    if not [item for item in validation_response if not(item[1])]:
      # If form input is valid
      username=formset_lookup['username']
      c=db.GqlQuery("Select * FROM User WHERE username = '%s'" %username)
      matchinguser=c.fetch(limit=10)
      
      if not matchinguser:
        password=formset_lookup['password']
        hashresult=makehash(username+password,makesalt())
        curr_user=User(username=username,passhash="{}|{}".format(hashresult[0],hashresult[1]))
        curr_user.put()

        self.makeusercookie(curr_user)        
        self.redirect("/user_reg/welcome")
      
      else:
        errorlist=[("user_error","That user already exists.")]
   
    else:
      # If form input is not valid
      errorlist=[(item[0],errordict[item[0]]) 
        for item in validation_response if not(item[1])]
        
    outputsubs=formset
    outputsubs.extend(errorlist)
    output_dict=dict(outputsubs)
      
    self.render('form_signup.html',**output_dict)

class Login(Handler):
    
  def input_validate (self, **kw):
    return [("user_error",USER_RE.match(kw['username'])),
      ("pass_error",PASS_RE.match(kw['password']))]

  def get(self):
    self.render('form_login.html')

  def post(self):
    formset=self.collect_input()
    formset_lookup=dict(formset)
    
    validation_response=self.input_validate(**formset_lookup)
    errorlist=[]

    if not [item for item in validation_response if not(item[1])]:
      # If form input is valid
      username=formset_lookup['username']
      password=formset_lookup['password']

      c=db.GqlQuery("Select * FROM User WHERE username = '%s'" %username)
      matchingusers=c.fetch(limit=1)
      
      if matchingusers:
        curr_user=matchingusers[0]
        match_passhash=curr_user.passhash.split('|')
        
        if checkhash(match_passhash[0],username+password,match_passhash[1]):
          self.makeusercookie(curr_user)
          self.redirect("/user_reg/welcome")
        else:
          errorlist=[("pass_error","Incorrect password")]
      
      else:
        errorlist=[("user_error","Username not found.")]
   
    else:
      # If form input is not valid
      errorlist=[(item[0],errordict[item[0]]) 
        for item in validation_response if not(item[1])]
        
    outputsubs=formset
    outputsubs.extend(errorlist)
    logging.info(outputsubs)
    output_dict=dict(outputsubs)
      
    self.render('form_login.html',**output_dict)

class Logout(Handler):
    
  def get(self):
    self.response.headers.add_header('Set-Cookie', 'userID=; Path=/')
    self.redirect('/user_reg/signup')

class WelcomeHandler(Handler):

  def get(self):
    # logging.info("welcome page!!")
    if self.user:
        self.render('home.html',user=self.user)
        cookie=self.request.cookies.get('user_ID')
        logging.info(cookie)
    else:
      self.redirect("/user_reg/signup")
    
app = webapp2.WSGIApplication([
  ('/user_reg/signup', Register),
  ('/user_reg/login', Login),
  ('/user_reg/logout', Logout),
  ('/user_reg.?', MainPage),
  ('/user_reg/welcome.*',WelcomeHandler)
], debug=True)
