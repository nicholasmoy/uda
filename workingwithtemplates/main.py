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
from collections import defaultdict
import logging
import jinja2
import os

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir))


header="""
  <head>
    <title>Sign Up</title>
    <style type="text/css">
      .label {text-align: right}
      .error {color: red}
    </style>

  </head>
"""

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
errordict=defaultdict(lambda:"",errorset)

formelements=("username","password","verify","email")


def escape_html(s):
  return cgi.escape(s,quote=True)

class Handler(webapp2.RequestHandler):
  def write(self, *a,**kw):
    self.response.out.write(*a,**kw)

  def render_str(self, template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

  def render (self, template, **kw):
    self.write(self.render_str(template,**kw))

class MainPage(Handler):
    
    def input_validate (self, dictionary= None):
      if not dictionary: dictionary= defaultdict(lambda:"",{("","")})
      passmatch_error=dictionary['password']==dictionary['verify']
      email_error=True

      if dictionary['email']:
        email_error=EMAIL_RE.match(dictionary['email'])

      return zip(errorhandles,(USER_RE.match(dictionary['username']),PASS_RE.match(dictionary['password']),passmatch_error,email_error))

    
    def get(self):
      self.response.out.write(header)
      self.render('workingwithtemplates.html')

    def post(self):
      input_orig=[]

      for i in range(0,len(formelements)):
        input_orig.append(self.request.get(formelements[i]))

      for i in range(0,len(input_orig)):
        input_orig[i]=escape_html(input_orig[i])
      
      formset=zip(formelements,input_orig)
      outputsubs=formset
      
      formset_lookup=defaultdict(lambda:"",formset)
      validation_response=self.input_validate(formset_lookup)


      if not [item for item in validation_response if not(item[1])]:
        outputsubs.extend([("successmessage","Success!")])
      else:
        errorlist=[]
        for i in range(0, len(validation_response)):
          if not(validation_response[i][1]):
            errorlist.append((validation_response[i][0],errordict[validation_response[i][0]]))

        
        outputsubs.extend(errorlist)
      
      output_dict=dict(outputsubs)
      logging.info(output_dict)
      
      self.response.out.write(header)
      self.write(self.render_str('workingwithtemplates.html',**output_dict))


app = webapp2.WSGIApplication([
  ('/workingwithtemplates.?', MainPage
)], debug=True)
