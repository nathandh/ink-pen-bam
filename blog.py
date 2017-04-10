# Nathan D Hernandez
# Udacity - FullStack Nano Degree 
# 
# Intro To Backend - BLOG App
import os, string, re
import hashlib, random
import webapp2
import jinja2

# Google App Engine DataStore
from google.appengine.ext import db

# Template directory specific
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                        autoescape = True)
"""
HASHING SPECIFIC
"""
class Hasher():
    def make_salt(self):
        salt = random.sample(string.ascii_lowercase, 5)
        return ''.join(salt)

    """
    Lookup salt by a username
    Assumes 'username' field is unique, and retrieves 1st record that matches
    """
    def lookup_salt(self, username):
        q = db.GqlQuery("SELECT * FROM User WHERE username = :username", username=username)
        # Get the 1st record result
        user = q.get()
        print "User * %s * retrieved...." % user.username
        print "Salt is: %s" % user.salt
    
    def hash_str(self, s):
        return hashlib.sha256(s).hexdigest()

    """
    Makes a secure password for storing into our database.
    Returns Hashed Password and Salt as Tuple for later verification
    """
    def make_pw_hash(self, name, pw, salt = None):
        if salt == None:
            salt = self.make_salt()
        return "%s|%s" % (self.hash_str(name + pw + salt), salt)
    
    """
    Checks against stored data, to see if PW submitted = Stored Hash PW
    """
    def check_pw_hash(self, user_obj, submitted_password):
        #print "Submitted Password Received: %s" % submitted_password
        #print "User Obj Received: %s" % str(user_obj)
        pass_hash = self.make_pw_hash(user_obj.username, submitted_password, user_obj.salt).split('|')
            
        if pass_hash != None and pass_hash[0] == user_obj.password:
            return True 
"""
END HASHING SPECIFIC
"""

"""
Handler class for app Helper Methods
"""
class Handler(webapp2.RequestHandler):
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.response.write(self.render_str(template, **kw))

"""
USER App Engine Entity for persistance
"""
class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()
    salt = db.StringProperty(required = True)

"""
Handles the Main USER operations
"""
class UserHandler():
    def create_user(self, username, password, email = None):
        hashed_pass = Hasher().make_pw_hash(username, password).split('|')
        if hashed_pass:
            my_pass = hashed_pass[0]
            my_salt = hashed_pass[1]
            user = User(username=username, password=my_pass, salt=my_salt)
            key = user.put()
            my_user = User.get(key)
        return my_user

    # Cookie Related functions
    def check_cookie(self, web_obj, user):
        user_cookie = web_obj.request.cookies.get('user_id')
        print user_cookie

    def set_cookie(self, web_obj, user):
        cookie_data = "%s|%s" % (str(user.username), str(user.password))
        web_obj.response.headers.add_header('Set-Cookie', 'user_id=%s; path=/;' % cookie_data)
        if cookie_data != None:
            return True

    def delete_cookie(self, web_obj, user):
        web_obj.response.delete_cookie('user_id', path='/')
        return True

    # Signup/Registration Form Specific helper functions
    def valid_username(self, username):
        # Validate Username
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return USER_RE.match(username)

    def valid_password(self, password):
        # Validate Password
        PASS_RE = re.compile(r"^.{3,20}$")
        return PASS_RE.match(password)

    def valid_email(self, email):
        # Validate Email
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        return EMAIL_RE.match(email)

    def user_logged_in(self, web_obj):
        user_info = web_obj.request.cookies.get('user_id')
        user_logged_in = False
        
        if user_info:
            user_info = user_info.split('|')
            user_id = user_info[0]
            hashed_pass = user_info[1]

            if user_id != None and hashed_pass != None:
                user_logged_in = True
                return user_info
            else:
                print "No User Logged in...."
        else:
            print "No User Logged in...."

        if user_logged_in == False:
            return None

    def user_loggedin_valid(self, web_obj, user_info):
        user_valid = False

        if user_info:
            user_id = user_info[0]
            hashed_pass = user_info[1]

            # First use UserSignup function to see if user exists
            user = self.user_exists(user_id)
            if user:
                #Next validate hashed_pass matches what is DB
                if user.password == hashed_pass:
                    user_valid = True
            else:
                print "Invalid User and Cookie set"

        if user_valid == True:
            return user

    # Checks whether a user exists in the DataStore
    def user_exists(self, username):
        # Check if USER already exists in DataStore
        q = db.GqlQuery("SELECT * FROM User WHERE username = :username", username=username)
        # Get the 1st record result
        user = q.get()
        #print "in User exists %s" % user
        #print User.all().get().username
        return user

    # Verifies User entered Password on Forms matches what we expect from DataStore
    def user_verify_pass(self, user_obj, submitted_password):
        # Validate against Hasher().check_pw_hash function
        if Hasher().check_pw_hash(user_obj, submitted_password):
            return True

class UserSignup(Handler):
    def get(self):
        self.render("user-signup.html", username_validation="", password_validation="", 
                    verify_validation="", email_validation="")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        #print username

        user_validation = ""
        pass_validation = ""
        pass2_validation = ""
        mail_validation = ""

        validation_error = False
       
        #print self.valid_username(username)
        if UserHandler().valid_username(username) == None:
            user_validation="That's not a valid username."
            validation_error = True
        if username:
            if UserHandler().user_exists(username) != None:
                user_validation="Username already exists, please choose another!"
                validation_error = True
        if UserHandler().valid_password(password) == None:
            pass_validation="That wasn't a valid password."
            validation_error = True
        if UserHandler().valid_password(password) != None:
            if verify != None and verify != password:
                    pass2_validation = "Your passwords didn't match."
                    validation_error = True
        if email != "":
            if UserHandler().valid_email(email) == None:
                mail_validation="That's not a valid email."
                validation_error = True

        self.render("user-signup.html", username=username, email=email, 
                    username_validation=user_validation, password_validation=pass_validation, 
                    verify_validation=pass2_validation, email_validation=mail_validation)

        if validation_error == False:
            user = UserHandler().create_user(username, password, email)
            if user != None:
                # Set our User Cookie
                UserHandler().set_cookie(self, user)
            else:
                print ("USER not created ERROR!")

            # Redirect to Welcome, as validation_error is False
            self.redirect("/blog/welcome")

"""
POST Google App Engine Entity for persistance
"""
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_content = self.content.replace('\n', '<br />')
        return Handler().render_str("post.html", post=self)

"""
Handler for individual posts permalinks
"""
class PostHandler(Handler):
    def get(self, post_id):
        #print post_id
        post = Post.get_by_id(long(post_id))
    
        if post != None:
            self.render("permalink.html", permalink=post_id, post=post)
        else:
            self.redirect("/blog")
    
    def post(self, post_id):
        url_post_id = post_id
        method = self.request.get("_method").upper()
        post_id = self.request.get("post_id")

        if url_post_id == post_id:
            if method == "DELETE":
                # Delete our Post
                self.delete_post(post_id)

    def delete_post(self, post_id):
        post = Post.get_by_id(long(post_id))

        if post != None:
            post.delete()
    
        # Check to make sure post is deleted
        post_check = Post.get_by_id(long(post_id))
        print "Post Check returned: %s" % post_check
        
        # Redirect if Post instance deleted successfully
        if post_check == None:
            self.redirect("/blog")
        else:
            print "DELETE of POST instance failed!"

"""
New Post URL Handler, for our blog post additions
"""
class NewPost(Handler):
    def add_new_post(self, subject, content):
        p = Post(subject=subject, content=content)
        p.put() 

        #print p
        self.redirect("/blog/%s" % p.key().id())

    def get(self):
        self.render("newpost.html", subject_validation="", content_validation="")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        #print "Subject is %s, and Content is %s" % (subject, content)

        subject_validation = ""
        content_validation = ""

        validation_error = False

        if subject == "":
            subject_validation = "You must enter a SUBJECT before submitting..."
            validation_error = True

        if content == "":
            content_validation = "You must enter CONTENT text before submitting..."
            validation_error = True

        """
        If all is well, add the post...Otherwise render the page with errors
        """
        if validation_error == False:
            self.add_new_post(subject, content)
        else:
            self.render("newpost.html", subject=subject, content=content, 
                    subject_validation=subject_validation, content_validation=content_validation)

""" 
Main BLOG Front Page Handler
"""
class Blog(Handler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
        # Output post.ids for debugging
        #for post in posts: 
        #    print post.key().id()

        self.render("blog.html", posts=posts)
    
    def post(self):
        self.render("blog.html")

        
class Welcome(Handler):
    def get(self):
        user_logged_in = False
        user_valid = False
        user_info = UserHandler().user_logged_in(self)
        
        if user_info:
            # Then some User cookie does exist
            user_logged_in = True
        
            # NEXT, Check validity of cookie info against what is in DataStore
            user = UserHandler().user_loggedin_valid(self, user_info)

            if user:
                user_valid = True
                username = user.username
                self.render("welcome.html", username=username)
        else:
            print "We don't have a cookie set yet!"
            
        if user_logged_in == False or user_valid == False:
            self.redirect("/blog/signup")
    
class Login(Handler):
    def get(self):
        self.render("login.html", validation_error="")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        
        # Error MSG we render on out html page
        login_error = "Invalid Login"   
        
        # Becomes True if error is found
        validation_error = False

        # 1st Check if User entered exists 
        user = UserHandler().user_exists(username)
        if user != None:
            #print "User exists in our DataStore...."
            # User matches a User in DataStore
            # 2nd Check if Password entered was correct
            if UserHandler().user_verify_pass(user, password):
                print "Password matches our DataStore...."
                if UserHandler().set_cookie(self, user):
                    self.redirect("/blog/welcome")
                else:
                    print "Problem setting cookie..."
            else:
                validation_error = True
        else:
            validation_error = True

        self.render("login.html", login_error=login_error)

class Logout(Handler):
    def get(self):
        user_info = self.request.cookies.get('user_id')
        
        if user_info != None:
            user_info = user_info.split('|')
            user_id = user_info[0]
           
            # Grab our User
            user = UserHandler().user_exists(user_id)
            if user:
                # Delete our Cookie
                UserHandler().delete_cookie(self, user)
        
        # Redirect to Signup page
        self.redirect("/blog/signup")

"""
Catch-All Blog Router
"""
class BlogRouter(Handler):
    def get(self):
        self.redirect("/blog")

app = webapp2.WSGIApplication([
    ('/blog', Blog),
    ('/blog/signup', UserSignup),
    ('/blog/welcome', Welcome),
    ('/blog/login', Login),
    ('/blog/logout', Logout),
    ('/blog/newpost', NewPost),
    ('/blog/*', BlogRouter),
    ('/*', BlogRouter),
    webapp2.Route(r'/blog/<post_id:\d+>', handler=PostHandler, name='post'),
], debug=True)
