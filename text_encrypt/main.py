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

form="""
  <form method="post" action="/text_encrypt">
    <input type="textarea" name="text" value="%(form_text)s">
    <input type="submit">
  </form>
  <br>
  Original Text: %(orig_text)s
"""

class MainPage(webapp2.RequestHandler):
    def write_form(self,form_text="",orig_text=""):
      self.response.out.write(form % {
        "form_text":form_text,
        "orig_text":orig_text
        })

    def rot(self,text="",n=0):
      text=text.encode('utf-8')
      lc=string.ascii_lowercase
      uc=string.ascii_uppercase
      trans= string.maketrans(lc+uc,lc[n:]+lc[:n]+uc[n:]+uc[:n])
      return text.translate(trans)

    def get(self):
      self.write_form()

    def post(self):
      orig_text=self.request.get("text")
      form_text=self.rot(orig_text,13)
      self.write_form(form_text,orig_text)

        
app = webapp2.WSGIApplication([
  ('/text_encrypt', MainPage)
], debug=True)
