
from google.appengine.ext import db

class blogPost(db.Model):
	title=db.StringProperty(required=True)
	post = db.TextProperty (required=True)
	createdtime=db.DateTimeProperty(auto_now_add = True)