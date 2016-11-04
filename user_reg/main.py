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


header="""
  <head>
    <title>Sign Up</title>
    <style type="text/css">
      .label {text-align: right}
      .error {color: red}
    </style>

  </head>
"""

form="""
  <h2>Signup</h2>
  <form method="post" action="/user_reg">
    <table>
      <tr>
        <td class="label">Username:</td>
        <td> 
          <input type="text" name="username" value="%(username)s">
        </td>
        <td class="error">%(user_error)s</td>
      </tr>
      <tr>
        <td class="label">Password:</td>
        <td> 
          <input type="password" name="password">
        </td>
        <td class="error">%(pass_error)s</td>
      </tr>
      <tr>
        <td class="label">Verify Password:</td>
        <td> 
          <input type="password" name="verify">
        </td>
        <td class="error">%(passmatch_error)s</td>
      </tr>
      <tr>
        <td class="label">E-mail:</td>
        <td> 
          <input type="text" name="email" value="%(email)s">
        </td>
        <td class="error">%(email_error)s</td>
      </tr>
    </table>
    <input type="submit">
  </form>
  <br>
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

class MainPage(webapp2.RequestHandler):
    
    def input_validate (self, dictionary= None):
      if not dictionary: dictionary= defaultdict(lambda:"",{("","")})
      passmatch_error=dictionary['password']==dictionary['verify']
      email_error=True

      if dictionary['email']:
        email_error=EMAIL_RE.match(dictionary['email'])

      return zip(errorhandles,(USER_RE.match(dictionary['username']),PASS_RE.match(dictionary['password']),passmatch_error,email_error))

    def write_form (self, dictionary= None):
      if not dictionary: dictionary= defaultdict(lambda:"",{("","")})
      self.response.out.write(form % dictionary)
    
    def get(self):
      self.response.out.write(header)
      self.write_form()

    def post(self):
      input_orig=[]

      for i in range(0,len(formelements)):
        input_orig.append(self.request.get(formelements[i]))

      for i in range(0,len(input_orig)):
        input_orig[i]=escape_html(input_orig[i])
      
      formset=zip(formelements,input_orig)
      
      formset_lookup=defaultdict(lambda:"",formset)
      validation_response=self.input_validate(formset_lookup)


      if not [item for item in validation_response if not(item[1])]:
        self.redirect("/user_reg/welcome?username="+formset_lookup['username'])
      else:
        errorlist=[]
        for i in range(0, len(validation_response)):
          if not(validation_response[i][1]):
            errorlist.append((validation_response[i][0],errordict[validation_response[i][0]]))

        outputsubs=formset
        outputsubs.extend(errorlist)
        output_dict=defaultdict(lambda:"",outputsubs)
        self.response.out.write(header)
        
        self.write_form(output_dict)


class WelcomeHandler(webapp2.RequestHandler):
  def get(self):
    username=self.request.get('username')
    logging.info("username "+username)
    self.response.out.write("Welcome, "+username+"!")

app = webapp2.WSGIApplication([
  ('/user_reg.?', MainPage),('/user_reg/welcome.*',WelcomeHandler)
], debug=True)
