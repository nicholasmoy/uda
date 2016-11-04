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
import jinja2
import os
from dataclasses import blogPost
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

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
    def render_front(self):
      blogPosts = db.GqlQuery("Select * FROM blogPost "
        "ORDER BY createdtime DESC")
      logging.info(blogPosts)
      self.render('home.html', blogPosts=blogPosts)

    def get(self):
      self.render_front()


class NewPost(Handler):
    def render_NewPost(self,*a, **kw):
      self.render('newpost.html',*a, **kw)

    def get (self):
      self.render_NewPost()

    def post (self):
      title=self.request.get("subject")
      post=self.request.get("content")

      errorlist={}

      if not title: errorlist['title_error']="Your blog post needs a Subject Heading!"
      if not post: errorlist['post_error']="Your blog post needs Contents!"

      if errorlist: 
        self.render_NewPost(title=title, post=post, **errorlist)
      else:
        post=blogPost(title=title,post=post)
        post.put()
        postid=post.key().id()
        self.redirect('/basicblog/'+str(postid))

class PostHandler(Handler):
    def render_Post(self,*a, **kw):
      self.render('existingpost.html',*a, **kw)

    def get (self, **kw):
      post_id=kw['post_id']
      post = blogPost.get_by_id(int(post_id))
      if not post:
        self.error(404)
        return
      
      self.render_Post(post=post)


app = webapp2.WSGIApplication([
  ('/basicblog.?', MainPage),
  ('/basicblog/newpost.?', NewPost),
  webapp2.Route(r'/basicblog/<post_id:\d+>', PostHandler)
  ], debug=True)
