# Imports
from google.appengine.ext import db
import os
import webapp2
import jinja2
import hmac
import random
import string
import hashlib
import json
import pygments
from google.appengine.api import users
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from pygments import highlight
from pygments.lexers import PythonLexer
from pygments.formatters import HtmlFormatter
from time import time
import datetime
from contextlib import closing
from zipfile import ZipFile, ZIP_DEFLATED
import StringIO
import zipfile
from google.appengine.ext import webapp
from google.appengine.api import urlfetch


#The secret :O
SECRET="fhdsajfdsaaljfiwuejfds93oiwje9832uijwdcxzJSLKJFI89329ikndmschiuk"

#Set up Jinja2
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)


# Set up providers for signing in
providers = {
    'Google'   : users.create_login_url(federated_identity='www.google.com/accounts/o8/id'),
    'Yahoo'    : users.create_login_url(federated_identity='yahoo.com'),
    'MySpace'  : users.create_login_url(federated_identity='myspace.com'),
    'AOL'      : users.create_login_url(federated_identity='aol.com'),
    'MyOpenID' : users.create_login_url(federated_identity='myopenid.com')
}
# The admins
admins = [
    "AnthonyUdacity",
    "ShayanUdacity"           
]

#Database for users
class Users(db.Model):
    username=db.StringProperty(required = True)
    password=db.StringProperty(required = True)
    email=db.StringProperty(required = False)
    code = db.TextProperty(required = False)
    created=db.DateTimeProperty(auto_now_add = True)

#Database for submissions
class Content(db.Model):
    title=db.StringProperty()
    code=db.TextProperty()
    title2=db.TextProperty()
    code2=db.TextProperty()
    created=db.DateTimeProperty(auto_now_add = True)
    ups=db.IntegerProperty(default = 0)
    downs=db.IntegerProperty(default = 0)
    last_edit = db.DateTimeProperty()
    username = db.StringProperty(required = True)
    group_name = db.StringProperty(required = True)
    highlight_code = db.TextProperty()
    udacity_nickname = db.TextProperty()

#Database for groups
#class Groups(db.Model):
    #username = db.StringProperty(required = True)
    #group_name=db.StringProperty(required = True)
    #created=db.DateTimeProperty(auto_now_add = True)    

#Handler
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


import re
# Set cookies, add to database
def welcome(self, username, password, email):
    # set username as a cookie
    set_username=username
    
    new_cookie_val=make_secure_val(str(set_username))
    
    self.response.headers.add_header("Set-Cookie", "set_username=%s" % new_cookie_val)
    
    # add username, hash and salt to the database
    
    a = Users(username=username, password=password, email=email)
    a.put()
    
    self.redirect("/welcome")
#Check username
def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return USER_RE.match(username)

#Check password
def valid_password(password):
    USER_RE = re.compile(r"^.{3,20}$")
    return USER_RE.match(password)

#Verify Password
def valid_verify(verify, user_password):
    if verify==user_password:
        return verify
#Check email
def valid_email(email):
    USER_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    return USER_RE.match(email)

#Hash the string
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

#Cookie
def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

#Make salt
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

#Check value
def check_secure_val(h):
    val=h.split("|")[0]
    if h==make_secure_val(val):
        return val

#make hash
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

#Check password
def valid_pw(name, pw, h):
    salt = h.split(",")[1]
    if str(h.split(",")[0]) == str(make_pw_hash(name, pw, salt).split(",")[0]):
        x=1
    else:
        x=0
    return x

#Check if logged in then return username
def if_logged_in(self):
        user = users.get_current_user()
        set_username_cookie_str = self.request.cookies.get("set_username")
        if set_username_cookie_str:
            cookie_val = check_secure_val(set_username_cookie_str)
            if cookie_val:
                current_user = cookie_val
                return current_user
        if user:
            return user.nickname()
        return None
#Check how many times user submitted
def get_number_of_submits(self):
    current_user = if_logged_in(self)
    if current_user:
        submits = db.GqlQuery("SELECT * FROM Content WHERE username = :1", current_user)
        return submits.count()
#hash password
def encrypt_pass(username, password):
    pw_hash = make_pw_hash(username, password, salt = None)
    return pw_hash
#Signup the user
class Signup(Handler):
    def render_front(self, username="", email="", error1="", error2="", error3="", error4=""):
        self.render("signup.html", username=username, email=email, error1=error1, error2=error2, error3=error3, error4=error4)
    def get(self):
        current_user = if_logged_in(self)
        if current_user:
            self.redirect("/")
        self.render_front()
    def post(self):
        user_username = self.request.get('username')
        user_password = self.request.get('password')
        user_verify = self.request.get('verify')
        user_email = self.request.get('email')
        username = valid_username(user_username)
        password = valid_password(user_password)
        verify = valid_verify(user_verify, user_password)
        email = valid_email(user_email)
        
        a = db.GqlQuery("SELECT * FROM Users WHERE username=:1", user_username).get()
        
        if not (username and password and verify) or a:
            if not (username):
                thing1='Please enter a valid username.'
            else:
                thing1=''
            
            if not (password):
                thing2='Please enter a valid password.'
            else:
                thing2=''
            
            if not (verify):
                thing3='The passwords did not match.'
            else:
                thing3=''
            
            if len(user_email) > 0:
                if not (email):
                    thing4='Please enter a valid email address.'
                else:
                    thing4=''
            else:
                thing4=''
            if a:
                thing1='This username has already been taken.'
            self.render_front(user_username, user_email, thing1, thing2, thing3, thing4)    
        
        else:
            thing1=''
            thing2=''
            thing3=''
            if len(user_email) > 0:
                if not (email):
                    thing4='Please enter a valid email address.'
                    self.render_front(user_username, user_email, thing1, thing2, thing3, thing4)    
                else:
                    user_password = encrypt_pass(user_username, user_password)
                    welcome(self, user_username, user_password, user_email)
            else:
                user_password = encrypt_pass(user_username, user_password)
                welcome(self, user_username, user_password, user_email)    
#Make cookie
class WelcomeHandler(Handler):
    def get(self):
        set_username = None
        set_username_cookie_str = self.request.cookies.get("set_username")
        if set_username_cookie_str:
            cookie_val = check_secure_val(set_username_cookie_str)
            if cookie_val:
                set_username=str(cookie_val)
        self.redirect("/")

#Login
class LoginHandler(Handler):
    def render_front(self, username="", error=""):
        self.render("signin.html", username=username, error=error, providers = providers)
        
    def get(self):
        current_user = if_logged_in(self)
        if current_user:
            self.redirect("/")
        self.render_front()
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        a = db.GqlQuery("SELECT * FROM Users WHERE username=:1", username).get()
        if a:
            x=valid_pw(username, password, str(a.password))
            if x==1:
                set_username=username
    
                new_cookie_val=make_secure_val(str(set_username))
    
                self.response.headers.add_header("Set-Cookie", "set_username=%s" % new_cookie_val)
        
                self.redirect("/welcome")
    
            else:
                error="Invalid login"
                self.render_front(username=username, error=error)
        else:
            error="Invalid login"
            self.render_front(username=username, error=error)      

#logout
class LogoutHandler(Handler):
    def get(self):
    
        self.response.headers.add_header ("Set-Cookie", "set_username =; Path = /")
        
        self.redirect("/")  
   
#Front page     
class MainPage(Handler):
    def render_front(self, a="", your_entry = "", your_entry2 = ""):
        contents = db.GqlQuery("SELECT * FROM Content ORDER BY created")
        current_user = if_logged_in(self)
        if current_user:
            user = users.get_current_user()
            submits_number=get_number_of_submits(self)
            a = db.GqlQuery("SELECT * FROM Content WHERE username = :1", current_user).get()
            if a:
                if submits_number ==0:
                    already_submitted = None
                    your_entry = None

                elif submits_number == 1:
                    already_submitted = "1"
                    your_entry = a.key().id()

                else:
                    already_submitted = "2"
                    your_entry = a.key().id()
                    a = db.GqlQuery("SELECT * FROM Content WHERE username = :1 ORDER BY created DESC", current_user).get()
                    your_entry2 = a.key().id()
            else:
                already_submitted = None
            a = db.GqlQuery("SELECT * FROM Content WHERE group_name = :1 ORDER BY created DESC", "Rock Paper Scissors")
            if user:  # signed in already
                logout_url = users.create_logout_url("/")

                self.render("front.html", a = a, already_submitted = already_submitted, your_entry = your_entry, your_entry2 = your_entry2, current_user = current_user, admins = admins, user = user, nickname = user.nickname(), logout_url = logout_url, providers = providers)
            else:
                self.render("front.html", a = a, already_submitted = already_submitted, your_entry = your_entry, your_entry2 = your_entry2, current_user = current_user, admins = admins)
        else:
            a = db.GqlQuery("SELECT * FROM Content WHERE group_name = :1 ORDER BY created DESC", "Rock Paper Scissors")
            self.render("front.html", current_user = current_user, contents = contents, providers = providers, admins = admins)
    def get(self):
        current_user = if_logged_in(self)
        if current_user:
            a = db.GqlQuery("SELECT * FROM Content WHERE group_name = :1 ORDER BY created DESC", "Rock Paper Scissors")
            for content in a:
                if content.code:
                    content.highlight_code = highlight(content.code, PythonLexer(), HtmlFormatter())
                    content.put()
                else:
                    content.highlight_code = highlight(content.code2, PythonLexer(), HtmlFormatter())
                    content.put()
            self.render_front(a)
        else:
            self.render_front()



# Create new posts
class RPSNewPostHandler(Handler):
    def render_front(self, title="", code="", udacity_nickname="", error="", rps = "content", your_entry = "", contents = ""):
        contents = db.GqlQuery("SELECT * FROM Content ORDER BY created DESC")
        current_user = if_logged_in(self)
        if current_user:
            user = users.get_current_user()
            if user:  # signed in already
                logout_url = users.create_logout_url("/")
                self.render("newpost.html", rps = rps, udacity_nickname = udacity_nickname, your_entry = your_entry, current_user = current_user, user = user, nickname = user.nickname(), logout_url = logout_url, title=title, code=code, error=error, admins = admins)
            else:
                self.render("newpost.html", rps = rps, udacity_nickname = udacity_nickname, your_entry = your_entry, current_user = current_user, title=title, code=code, error=error, admins = admins)
        else:
            self.redirect("/")
    
    def get(self):
        contents = db.GqlQuery("SELECT * FROM Content WHERE group_name = :1", "Rock Paper Scissors")
        if contents:
            self.render_front(contents = contents)
        else:
            self.render_front()

    def post(self):
        title = self.request.get("title")
        code = self.request.get("code")
        udacity_nickname = self.request.get("udacity_nickname")
        current_user = if_logged_in(self)
        submits_number = get_number_of_submits(self)
        if submits_number >= 2:
            error = "You can only enter two submissions. <a class ='link' style='color:red;'href='/''>Click to google to the Homepage</a>"
            self.render_front(title, code, udacity_nickname, error)
        elif submits_number == 1:
            if title and code and udacity_nickname:
                group_name = "Rock Paper Scissors"
                a = Content(udacity_nickname = udacity_nickname, username = current_user, title2 = title, code2 = code, group_name = group_name, admins = admins)
                a.put()
                get_id=a.key().id()
                get_id=str(get_id)
                self.redirect("/"+get_id)
            else:
                error = "Please enter a title, a Udacity Nickname and some code!"
                self.render_front(title, code, udacity_nickname, error)
        else:
            if title and code and udacity_nickname:
                group_name = "Rock Paper Scissors"
                a = Content(udacity_nickname = udacity_nickname, username = current_user, title = title, code = code, group_name = group_name, admins = admins)
                a.put()
                get_id=a.key().id()
                get_id=str(get_id)
                self.redirect("/"+get_id)
            else:
                error = "Please enter a title, a Udacity Nickname and some code!"
                self.render_front(title, code, udacity_nickname, error)

#Handle new page
class NewPageHandler(Handler):
        
    def get(self, post_id):
        the_id=int(post_id)
        contents = db.GqlQuery("SELECT * FROM Content ORDER BY created DESC")
        contents=Content.get_by_id(the_id)
        if contents.title:
            title=contents.title
            code=contents.code
        else:
            title=contents.title2
            code=contents.code2
        created = contents.created
        last_edit = contents.last_edit
        code = highlight(code, PythonLexer(), HtmlFormatter())
        current_user = if_logged_in(self)
        if current_user:
            user = users.get_current_user()
            if user:  # signed in already
                logout_url = users.create_logout_url("/")
                self.render("specificpage.html", current_user = current_user, user = user, nickname = user.nickname(), logout_url = logout_url, title=title, code=code, created = created, last_edit = last_edit, contents = contents, admins = admins)
            else:
                self.render("specificpage.html", current_user = current_user, title=title, code=code, created = created, last_edit = last_edit, contents = contents, admins = admins)
        else:
            self.render("specificpage.html", title=title, code=code, created = created, last_edit = last_edit, contents = contents, admins = admins)

#Allow Editing
class EditHandler(Handler):
    def render_front(self, contents = ""):
        current_user = if_logged_in(self)
        if contents.username == current_user:
            pass
        else:
            self.redirect("/")
        if current_user:
            user = users.get_current_user()
            if user:  # signed in already
                logout_url = users.create_logout_url("/")
                self.render("edit.html", contents = contents, current_user = current_user, user = user, nickname = user.nickname(), logout_url = logout_url, admins = admins)
            else:
                self.render("edit.html", contents = contents, current_user = current_user, admins = admins)
        else:
            self.render("edit.html", contents = contents, admins = admins)

    def get(self, the_id):
        current_user = if_logged_in(self)
        the_id=int(the_id)
        contents=Content.get_by_id(the_id)
        if contents.username == current_user:
            self.render_front(contents)
        else:
            self.redirect("/")
    def post(self, the_id):
        title = self.request.get("title")
        code = self.request.get("code")
        if title and code:
            a = Content.get_by_id(int(the_id))
            if a.code:
                a.code = code
            else:
                a.code2 = code
            a.highlight_code = highlight(code, PythonLexer(), HtmlFormatter())
            if a.title:
                a.title = title
            else:
                a.title2 = title
            a.last_edit = datetime.datetime.now()
            a.put()
            get_id=a.key().id()
            get_id=str(get_id)
            self.redirect("/"+get_id)
        else:
            error = "Please enter a title and some code!"
            self.render_front(title, error)
#Allow viewing source code
class SourceHandler(Handler):
    def get(self, the_id):
        the_id=int(the_id)
        contents = db.GqlQuery("SELECT * FROM Content ORDER BY created DESC")
        contents=Content.get_by_id(the_id)
        if contents.title:
            title=contents.title
            code=contents.code
        else:
            title=contents.title2
            code=contents.code2
        created = contents.created
        last_edit = contents.last_edit
        current_user = if_logged_in(self)
        if current_user:
            user = users.get_current_user()
            if user:  # signed in already
                logout_url = users.create_logout_url("/")
                self.render("source.html", current_user = current_user, user = user, nickname = user.nickname(), logout_url = logout_url, title=title, code=code, created = created, last_edit = last_edit, contents = contents, admins = admins)
            else:
                self.render("source.html", current_user = current_user, title=title, code=code, created = created, last_edit = last_edit, contents = contents, admins = admins)
        else:
            self.render("source.html", title=title, code=code, created = created, last_edit = last_edit, contents = contents, admins = admins)

#Allow specific downloads
class downloadHandler(Handler):
    def get(self, the_id):
        the_id=int(the_id)
        contents = db.GqlQuery("SELECT * FROM Content ORDER BY created DESC")
        contents=Content.get_by_id(the_id)
        self.response.headers['Content-Disposition'] = 'attachment; filename = udacity_code'+`the_id`+'.py'
        current_user = if_logged_in(self)
        if current_user == contents.username or current_user in admins:
            code=[]
            if contents.code:
                code2 = contents.code
            else:
                code2 = contents.code2
            if contents.udacity_nickname:
                code.append("# First submitted by " + contents.udacity_nickname +" ("+contents.username+") on " + contents.created.strftime('%a, %b-%d-%Y, %H:%M %Z UTC'))
            else:
                code.append("# First Submitted by " +contents.username+" on " + contents.created.strftime('%a, %b-%d-%Y, %H:%M %Z UTC'))
            code.append("\n")
            code.append("# Submission ID number: " + str(contents.key().id()))
            code.append("\n")
            code.append(code2)
            code="".join(code)
            self.response.out.write(code)
        else:
            self.redirect("/")
#Allow downloading all submitted entries
class downloadAllHandler(Handler):
    def get(self):
        current_user = if_logged_in(self)
        if current_user in admins:
            contents = db.GqlQuery("SELECT * FROM Content ORDER BY created DESC")
            output = StringIO.StringIO()
            x=1
            with zipfile.ZipFile(output, 'w') as myzip:
                for content in contents:
                    if content.code:
                        code2=content.code
                        code=[]
                        if content.udacity_nickname:
                            code.append("# First submitted by " + content.udacity_nickname +" ("+content.username+") on " + content.created.strftime('%a, %b-%d-%Y, %H:%M %Z UTC'))
                        else:
                            code.append("# First Submitted by " +content.username+" on " + content.created.strftime('%a, %b-%d-%Y, %H:%M %Z UTC'))
                        code.append("\n")
                        code.append("# Submission ID number: " + str(content.key().id()))
                        code.append("\n")
                        code.append(code2)
                        code="".join(code)
                        myzip.writestr("udacity_code"+`x`+".py", code.encode("utf-8"))
                    else:
                        code2=content.code2
                        code=[]
                        if content.udacity_nickname:
                            code.append("# First submitted by " + content.udacity_nickname +" ("+content.username+") on " + content.created.strftime('%a, %b-%d-%Y, %H:%M %Z UTC'))
                        else:
                            code.append("# First submitted by " +content.username+" on " + content.created.strftime('%a, %b-%d-%Y, %H:%M %Z UTC'))
                        code.append("\n")
                        code.append("# Submission ID number: " + str(content.key().id()))
                        code.append("\n")
                        code.append(code2)
                        code="".join(code)
                        myzip.writestr("udacity_code"+`x`+".py", code.encode("utf-8"))
                    x+=1
            self.response.headers["Content-Type"] = "application/zip"
            self.response.headers['Content-Disposition'] = "attachment; filename=Udacity_Submissions.zip"
            self.response.out.write(output.getvalue())
        else:
            self.redirect("/")


#URLS
app = webapp2.WSGIApplication([('/', MainPage), 
                             ('/group/rock\spaper\sscissors/newpost', RPSNewPostHandler),
                             ('/(\d+)', NewPageHandler), 
                             ('/signup', Signup), 
                             ('/welcome', WelcomeHandler), 
                             ('/login', LoginHandler), 
                             ('/logout', LogoutHandler), 
                             ('/(\d+)/source', SourceHandler),
                             ('/(\d+)/download', downloadHandler),
                             ('/download', downloadAllHandler),
                             ('/(\d+)/edit', EditHandler)], 
                            debug=True)
