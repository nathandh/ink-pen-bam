# Nathan D Hernandez
# Udacity - FullStack Nano Degree 
# 
# Intro To Backend - BLOG App
import os, string, re, datetime
import hashlib, random
import webapp2
import jinja2

# Google App Engine DataStore
from google.appengine.ext import db

# webapp2 simple sessions
from webapp2_extras import sessions

# Template directory specific
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                        autoescape = True)

"""
HASHING SPECIFIC
"""
class Hasher():
    def get_secret_key(self):
        # Secret Key to make more secure password hash.
        # This is the same generated key as used in the CONFIG variable for sessions
        secret_key = None
        try:   
            keyfile = os.path.join(os.path.dirname(__file__), 'inkpenbam.key')
            if os.path.exists(keyfile):
                print "KEY_FILE exists....extracting SECRET_KEY..."
                file_handler = open(keyfile)
                secret_key = file_handler.read().strip()
                #print secret_key
            else:
                print "******MISSING KEY_FILE***********"
        except:
            print "===inkpenbam.key file does not exist, or cannot read===="
        finally:    
            return secret_key

    def make_salt(self):
        salt = random.sample(string.ascii_lowercase, 8)
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
        # Uses SHA256
        return hashlib.sha256(s).hexdigest()

    """
    Makes a secure password for storing into our database.
    Returns Hashed Password and Salt as Tuple for later verification
    """
    def make_pw_hash(self, name, pw, salt = None):
        SECRET_KEY = self.get_secret_key()
        if salt == None:
            salt = self.make_salt()
        return "%s|%s" % (self.hash_str(name + pw + SECRET_KEY + salt), salt)
    
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
    TOP Main User MSG Handling
    """
    def get_main_msg(self):
        print "GET main msgs called..."
        # Get the current main MSG
        try:
            if self.session.get('main_user_msgs') == None:
                print "No main_user_msgs set. Setting EMPTY value..."
                self.session['main_user_msgs'] = ""
        except:
            print "Error getting main msg in 'get_main_msg'..."
        finally: 
            return self.session.get('main_user_msgs')

    def set_main_msg(self, msg):
        print "SET main msgs called..."
        # Set the msg
        try:
            self.session['main_user_msgs'] = msg
            print "Set main_user_msgs to: %s" % self.get_main_msg()
        except:
            print "Error setting 'main_user_msgs'..."

    def clear_main_msg(self): 
        print "Clear main msgs called..."
        # Set MAIN User MSG Text to ""
        try:
            self.session['main_user_msgs'] = ""
        except:
            print "Session object doesn't exist yet...."

    def get_msg_type(self):
        print "GET msg type called..."
        # Get the current MSG type if available
        try:
            if self.session.get('msg_type') == None:
                print "No msg_type is set... Setting Empty Value (will default to NOTICE type)..."
                self.session['msg_type'] = ""
        except:
            print "Error getting msg type in 'get_msg_type'..."
        finally:
            return self.session.get('msg_type')
    
    def set_msg_type(self, msg_type):
        print "SET msg_type called..."
        # Set out type
        try: 
            self.session['msg_type'] = msg_type
            print "Set msg_type to: %s" % self.get_msg_type()
        except:
            print "Error setting 'msg_type'...."

    def clear_msg_type(self):
        print "Clear msg_type called..."
        # Set Default msg_type
        try:
            self.session['msg_type'] = ""
        except:
            print "Session object doesn't exist yet..."

    """
    Gets the referrer source from headers, parses and returns it
    """
    def get_ref_source(self):
        source = None
        try:
            ref = self.request.referrer.split('http://')[1]
            first_slash = ref.find('/')
            source = ref[first_slash: ]
        except:
            print "Can't parse HTTP Referrer."
        finally:
            print "Source retrieved was: %s" % source
            return source
    
    """
    Session MGMT Specific
    See the DOCs: http://webapp2.readthedocs.io/en/latest/api/webapp2_extras/sessions.html
    """

    def _get_jinja_variable_session(self):
        print "IN: Handler()._get_session()"
        # Get Jinja Global Environment Session object
        my_session = None
        try:
            # Uncomment for additional debugging
            #print "Curr cookie is: %s" % self.request.cookies.get('session')
        
            if self.request.cookies.get('session') == None:
                print("'session' COOKIE data does not exist yet...so deleting any leftover Jinja Globals")
                del jinja_env.globals['inkpenbam_session']

            my_session = jinja_env.globals.get('inkpenbam_session')
        except:
            print "No Jinja global 'session' exists to GET"
        finally:
            print "Exiting _get_session Request"
            return my_session

    def _set_jinja_variable_session(self):
        # SET Jinja Global Environment Session object (Needs to be updated before used in a View)
        print "...attempting to set Session object"
        try: 
            #self.response.delete_cookie('session', path='/')
            #self.response.set_cookie('session', path='/')
            jinja_env.globals['inkpenbam_session'] = self.session
            return self._get_jinja_variable_session()
        except:
            print "Error setting session in Handler()._set_session"
        finally:
            print "Exiting _set_session Request"
    
    def dispatch(self):
        # Get a sessions store for request
        self.session_store = sessions.get_store(request=self.request)

        try:
            # Dispatch request
            webapp2.RequestHandler.dispatch(self)
        finally:
            # Save session
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def session(self):
        # Returns a session using the default cookie key
        return self.session_store.get_session()

"""
USER App Engine Entity (Model) for persistance
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
            user = User(username=username, password=my_pass, email=email, salt=my_salt)
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

        # Duplicate this data in 'session' cookie for testing webapp2 simple sessions
        web_obj.session['username'] = user.username
        # Set some additional DEFAULT 'session' cookie variables
        #web_obj.session['post_5901353784180736_form_error'] = "Test"

        # Additionally set Jinja Global Environment to contain session data, If Not YET Set
        my_session = None
        try:
            my_session = jinja_env.globals.get('inkpenbam_session')
        except:
            jinja_env.globals['inkpenbam_session'] = web_obj.session

        if cookie_data != None:
            return True

    def delete_cookie(self, web_obj, user):
        web_obj.response.delete_cookie('user_id', path='/')
        
        # Also delete our TEST session cookie
        web_obj.response.delete_cookie('session', path='/')
       
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
        print "IN: UserSignup.Handler()"

        # 1st Check if User Logged on AND Valid. If so, redirect to /blog/welcome
        user_logged_in = False
        user_valid = False
        user_info = UserHandler().user_logged_in(self)

        if user_info:
            user_logged_in = True
            user = UserHandler().user_loggedin_valid(self, user_info)

            if user:
                print ("We have a USER that is LOGGED In and Valid")
                user_valid = True
                self.redirect("/blog/welcome")

        # Proceed with standard UserSignup process
        last_handler = None
        messages_viewed = 0
        try:
            last_handler = self.session.get("curr_handler")
            messages_viewed = self.session.get("messages_viewed")
        except:
            print "No Last Handler or Errors Viewed values exist"
        finally:
            self.session["curr_handler"] = "UserSignup"
        
        # Refresh our stored Jinja inkpenbam_session variable
        stored_jinja_session = self._get_jinja_variable_session()
        if stored_jinja_session == None:
            self._set_jinja_variable_session()
        
        # Get referrer souce
        source = self.get_ref_source()

        if source!= None:
            if messages_viewed == 1:
                # Clear our previous session messages to display clean page
                print "Previously displayed errors. So clearing..."
                self.clear_main_msg()
        
        # Get User Messages for display, if applicable
        main_user_msgs = self.get_main_msg()
        msg_type = self.get_msg_type()
        
        self.render("user-signup.html", username_validation="", password_validation="", 
                    verify_validation="", email_validation="", main_user_msgs=main_user_msgs, msg_type=msg_type)

        # Mark any Error msgs as viewed if applicable
        if self.get_main_msg != None and self.get_main_msg != "":
            self.session['messages_viewed'] = 1
            self._set_jinja_variable_session()

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

        main_user_msgs = None
        msg_type = None
        #Check if we have a validation error. If so, set msg to client
        if validation_error == True:
            print "We have a validation error....setting Main Msg for user..."
            self.clear_main_msg()
            self.clear_msg_type()
            self.set_main_msg("Signup Error(s) exist. Please check...")
            self.set_msg_type("error")
            main_user_msgs = self.get_main_msg()
            msg_type = self.get_msg_type()

            #Update session variables
            self.session["messages_viewed"] = 1
            self._set_jinja_variable_session()

        self.render("user-signup.html", username=username, email=email, 
                    username_validation=user_validation, password_validation=pass_validation, 
                    verify_validation=pass2_validation, email_validation=mail_validation,
                    main_user_msgs=main_user_msgs, msg_type=msg_type)

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
POST Google App Engine Entity (Model) for persistance
"""
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created_by = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_content = self.content.replace('\n', '<br />')
        return Handler().render_str("post.html", post=self)

    def render_short(self):
        # Shorten post content displayed (Except for permalink pages that use render() above)
        content_max = 225

        short_content = self.content.replace('\n', '<br />')
        permalink = "/blog/%s" % self.key().id()
        more_post_link = "&nbsp;<a href='%s'>...View More...</a>" % permalink
        if len(short_content) > content_max:
            short_content = short_content[:content_max] + more_post_link
        
        self._rendershort_content = short_content
        return Handler().render_str("post-short.html", post=self)

"""
Permalink Handler for individual posts permalink pages
"""
class PostHandler(Handler):
    def get(self, post_id):
        #print post_id
        post = Post.get_by_id(long(post_id))
    
        if post != None:
            if self._get_jinja_variable_session() != None:
                self.render("permalink.html", permalink=post_id, post=post)
            else:
                self.redirect("/blog")
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
            elif method == "EDIT-FORM-REQUEST":
                # This is a main post edit REQUEST, not direct edit action submit.
                subject = None
                content = None
                initial_render = "true"
                self.edit_post(post_id, subject, content, initial_render)
            elif method == "EDIT":
                # Edit our Post ACTION, Pass Subject/Content that was posted
                subject = self.request.get("subject")
                content = self.request.get("content")
                self.edit_post(post_id, subject, content)
            elif method == "LIKE":
                # Like a Post Request
                self.like_post(post_id)
            elif method == "COMMENT":
                # Comment on a Post Request
                self.comment_post(post_id)

    def delete_post(self, post_id):
        print "IN: PostHandler().delete_post()"
        self.session["curr_handler"] = "PostHandler"
        
        curr_post = Post.get_by_id(long(post_id))

        post_form_error = ""
        try:
            if self.session != None:
                if self.session.get('post_%s_form_error' % post_id) != None:
                    # Clear our Post Form Errors
                    self.clear_postform_errors(post_id)
            # Clear our Main MSG area
            self.clear_main_msg()
        except:
            print "Nothing exists in POST_FORM_ERROR value in session."

        print ("DELETE Post received")
        
        # Check for logged in/ valid user
        user_logged_in = False
        user_valid = False
        user_info = UserHandler().user_logged_in(self)
        user = None

        if user_info:
            user_logged_in = True
            user = UserHandler().user_loggedin_valid(self, user_info)
            if user:
                user_valid = True
            else:
                print "Cookie invalid @ PostHandler!"

        if user_logged_in == False or user_valid == False:
            print "Either NOT Logged In, or Not VALID..."
            # Clear existing session data (as not logged in)
            try:
                # Reset message for Clicked Post
                self.session['post_%s_form_error' % post_id] = "DELETE requires Login!"

                # Set MAIN User MSG Text
                print "post subject is: %s" % curr_post.subject
                post_short_tag = "'%s...'" % curr_post.subject[0:20]
                self.set_main_msg("Please <a href='/blog/login'>Login</a> to DELETE post: %s" % post_short_tag)
                self.set_msg_type("error")
                #self.session['main_user_msgs'] = "Please Login to EDIT post: %s" % post_short_tag

                print "After DELETE click, session data is: %s" % self.session

                # Set error message to NOT viewed
                self.session["messages_viewed"] = 0 
                
                # Update STORED Jinja global session variable (for potential use in templates)
                self._set_jinja_variable_session()

                #self.redirect("/blog") Redirecting to Login instead
                self.redirect("/blog/login")
            except:
                print "Cannot add session variable in DELETE Post"
        
            print "USER Not Logged in....for DELETE" 
        
        if user_logged_in == True and user_valid == True:
            # Then we have a user valid user logged in and can proceed toward deleting post

            # Used in Notice to User below on successful delete
            post_subject = curr_post.subject[:20]
            
            # Check that DELETE clicker is POST created_by OWNER
            if curr_post.created_by == user.username:
                print "User is OWNER of Post. *CAN* Delete"
                # Post Deletion
                if curr_post != None:
                    curr_post.delete()
            
                # Check to make sure post is deleted
                post_check = Post.get_by_id(long(post_id))
                print "Post Check returned: %s" % post_check
                
                # Redirect if Post instance deleted successfully
                if post_check == None:
                    # Display notice message saying that post was deleted
                    self.clear_main_msg()
                    self.clear_msg_type()
                    self.set_main_msg('Success in deleting Post: "%s"' % post_subject)  
                    self.set_msg_type("notice")
                    
                    # Update session variables
                    # Update session to reflect this user as post owner
                    del self.session["post_%s_owner" % post_id]
                    self.session["messages_viewed"] = 0
                    self._set_jinja_variable_session()
                    self.redirect("/blog/welcome")
                else:
                    print "DELETE of POST instance failed!"
            # USER is NOT OWNER of POST. So Can't DELETE
            else:
                print "*ERROR in DELETING post with logged in AND valid user*"
                # Display error message saying that you need to be post Owner to DELETE
                self.clear_main_msg()
                self.clear_msg_type()
                self.set_main_msg("You can ONLY delete your own posts...")
                self.set_msg_type("error")
                
                # Update session variables
                self.session["messages_viewed"] = 0
                self._set_jinja_variable_session()

                self.redirect("/blog/welcome")

    def edit_post(self, post_id, subject, content, initial_render=None):
        print "IN: PostHandler().edit_post()"
        self.session["curr_handler"] = "PostHandler"
        
        curr_post = Post.get_by_id(long(post_id))
        
        # Used in Notice to User below on successful delete
        post_subject = curr_post.subject[:20]

        post_form_error = ""
        try:
            if self.session != None:
                if self.session.get('post_%s_form_error' % post_id) != None:
                    post_form_error = self.session.get('post_%s_form_error' % post_id)
                
                    print "*Post_FORM_ERROR: %s" % post_form_error
                    
                    # Clear Post Form Errors
                    self.clear_postform_errors(post_id)
                    
            # Clear our Main MSG area
            self.clear_main_msg()
           # self.session['main_user_msgs'] = ""
        except:
            print "Nothing exists in POST_FORM_ERROR value in session."

        print ("EDIT Post received")
        print ("post_form_error val currently set to: " + post_form_error)
        user_logged_in = False
        user_valid = False
        user_info = UserHandler().user_logged_in(self)
        user = None

        if user_info:
            user_logged_in = True
            user = UserHandler().user_loggedin_valid(self, user_info)
            if user:
                user_valid = True
            else:
                print "Cookie invalid @ PostHandler!"

        if user_logged_in == False or user_valid == False:
            print "Either NOT Logged In, or Not VALID...."
            # Clear existing session data (as not logged in)
            try:
                # Reset message for Clicked Post
                self.session['post_%s_form_error' % post_id] = "Must Login to EDIT!"

                # Set MAIN User MSG Text
                print "post subject is: %s" % curr_post.subject
                post_short_tag = "'%s...'" % curr_post.subject[0:20]
                self.set_main_msg("Please <a href='/blog/login'>Login</a> to EDIT post: %s" % post_short_tag)
                self.set_msg_type("error")
                #self.session['main_user_msgs'] = "Please Login to EDIT post: %s" % post_short_tag

                print "After EDIT click, session data is: %s" % self.session

                # Set error message to NOT viewed
                self.session["messages_viewed"] = 0 
                
                # Update STORED Jinja global session variable (for potential use in templates)
                self._set_jinja_variable_session()
                
                #self.redirect("/blog")  #Redirecting to Login instead
                self.redirect("/blog/login")
            except:
                print "Cannot add session variable in Edit Post"
        
            print "USER Not Logged in....for EDIT" 
        
        if user_logged_in == True and user_valid == True:
            # Then we have a user valid user logged in and can proceed toward EDITING post

            # Check that EDIT clicker is POST created_by OWNER
            if curr_post.created_by == user.username:
                print "User is OWNER of Post. *CAN* Edit"
                # Post Edit
                if curr_post != None:
                    #EDIT POST HERE
                    if ((subject == None and content == None) or (subject == "" or content == "")):
                        # Render our EditPost page for post editing
                        if (initial_render == "true"):
                            print "Initial EDIT-FORM-REQUEST received...."
                            # Set our default form values to what is in datastore
                            subject = curr_post.subject
                            content = curr_post.content
                        
                        subject_validation = ""
                        content_validation = ""
                        validation_error = False

                        if subject == "":
                            subject_validation = "Post must contain a SUBJECT before submit..."
                            validation_error = True

                        if content == "":
                            content_validation = "Post must contain CONTENT before submit..."
                            validation_error = True
                        
                        main_user_msgs = ""
                        msg_type = None

                        if validation_error == True:
                            print "We have a validation error...Setting Main MSG for user..."
                            self.clear_main_msg()
                            self.clear_msg_type()
                            self.set_main_msg("Edit values missing...")
                            self.set_msg_type("error")
                            main_user_msgs = self.get_main_msg()
                            msg_type = self.get_msg_type()

                            #Update session variables
                            self.session["messages_viewed"] = 1
                            self._set_jinja_variable_session()

                        self.render("editpost.html", post=curr_post, subject=subject, content=content, 
                        subject_validation=subject_validation, content_validation=content_validation,
                        main_user_msgs=main_user_msgs, msg_type=msg_type)
                    else: 
                        # Use the values from the request
                        print "Post subject and content received...Performing Update...."
                        curr_post.subject=subject
                        curr_post.content=content
                        curr_post.put()
            
                        # Check to make sure post still exists
                        post_check = Post.get_by_id(long(post_id))
                        print "Post Check returned: %s" % post_check
                
                        # Notify if can't find Post instance for some reason
                        if post_check == None:
                            print "CANNOT find Post instance!"
                        else:
                            print "SUCCESS Editing Post instance!"
                            # Display notice message saying that post was Edited
                            self.clear_main_msg()
                            self.clear_msg_type()
                            self.set_main_msg('Success in editing Post: "%s"' % post_subject)  
                            self.set_msg_type("notice")
                            
                            # Update session variables
                            self.session["messages_viewed"] = 0
                            self._set_jinja_variable_session()
                            
                        self.redirect("/blog/welcome") 
            # USER is NOT OWNER of POST. So Can't EDIT
            else:
                print "*ERROR in EDITING post with logged in AND valid user*"
                # Display error message saying that you need to be post Owner to EDIT
                self.clear_main_msg()
                self.clear_msg_type()
                self.set_main_msg("You can ONLY edit your own posts...")
                self.set_msg_type("error")
                
                # Update session variables
                self.session["messages_viewed"] = 0
                self._set_jinja_variable_session()

                self.redirect("/blog/welcome")

    def like_post(self, post_id):
        print "IN: PostHandler().like_post()"
        self.session["curr_handler"] = "PostHandler"
        
        curr_post = Post.get_by_id(long(post_id))

        post_form_error = ""
        try:
            if self.session != None:
                if self.session.get('post_%s_form_error' % post_id) != None:
                    # Clear our Post Form Errors
                    self.clear_postform_errors(post_id)
            # Clear our Main MSG area
            self.clear_main_msg()
        except:
            print "Nothing exists in POST_FORM_ERROR value in session."

        print ("LIKE Post received")
        
        # Check for logged in/ valid user
        user_logged_in = False
        user_valid = False
        user_info = UserHandler().user_logged_in(self)
        user = None

        if user_info:
            user_logged_in = True
            user = UserHandler().user_loggedin_valid(self, user_info)
            if user:
                user_valid = True
            else:
                print "Cookie invalid @ PostHandler!"

        if user_logged_in == False or user_valid == False:
            print "Either NOT Logged In, or Not VALID..."
            # Clear existing session data (as not logged in)
            try:
                # Reset message for Clicked Post
                self.session['post_%s_form_error' % post_id] = "LIKE requires Login!"

                # Set MAIN User MSG Text
                print "post subject is: %s" % curr_post.subject
                post_short_tag = "'%s...'" % curr_post.subject[0:20]
                self.set_main_msg("Please <a href='/blog/login'>Login</a> to LIKE post: %s" % post_short_tag)
                self.set_msg_type("error")

                print "After LIKE click, session data is: %s" % self.session

                # Set error message to NOT viewed
                self.session["messages_viewed"] = 0 
                
                # Update STORED Jinja global session variable (for potential use in templates)
                self._set_jinja_variable_session()

                #self.redirect("/blog") Redirecting to Login instead
                self.redirect("/blog/login")
            except:
                print "Cannot add session variable in LIKE Post"
        
            print "USER Not Logged in....for LIKE" 
        
        if user_logged_in == True and user_valid == True:
            # Then we have a user valid user logged in and can proceed toward liking post

            # Used in Notice to User below on successful delete
            post_subject = curr_post.subject[:20]
            
            # Check that LIKE clicker is NOT the POST created_by OWNER
            if curr_post.created_by != user.username:
                print "User is NOT OWNER of Post so *CAN* Like"
                # Post Like Allowed
                if curr_post != None:
                    print "Checking to see if 'user' has liked this post before"
                    
                    my_post_likes = curr_post.post_likes.filter('user =', user)
                    if my_post_likes.get() == None:
                        print "No LIKE exists for this USER on this post...."
                        print "*****Marking Post as LIKED by USER 1st time*****"
                        like = Like(post=curr_post, user=user, liked="true")
                        key = like.put()
          
                        # Validate like for user exists now
                        like_check = Like.get(key)
                        print "New post LIKE is: %s" % like_check
                        
                        # Set Messages and Redirect back to Welcome Home Page
                        # Display notice message saying that post was liked
                        self.clear_main_msg()
                        self.clear_msg_type()
                        self.set_main_msg('LIKED Post: "%s"' % post_subject)  
                        self.set_msg_type("notice")
                        
                        # Update session variables
                        self.session["messages_viewed"] = 0

                        self.session["like_%s_status" % curr_post.key().id()] = "true"

                        self._set_jinja_variable_session()
                        self.redirect("/blog/welcome")
                    else:
                        print "USER has liked this post before..."

                        """
                        The following should never occur under normal operation.
                        i.e. there should never be more than 1 Like per User for a Post
                        This exists purely as a failsafe cleanup..., and for convenience
                        while testing out Liking Posts during development
                        """
                        if my_post_likes.count() > 1:
                            print "Cleaning House. Should only be 1 Post Like Per User"
                            count = 0
                            for my_like in my_post_likes:
                                if count == 0:
                                    print "Keeping 1 Like: %s" % my_like
                                else:
                                    print "Deleting extra like"
                                    my_like.delete()

                                count += 1
                        
                        # This output should always be 1 only per user
                        print "# of Times User has Liked this post: %s" % my_post_likes.count()

                        # Set our like to true/false, rather than delete completely to indicate user 
                        # has previously liked an item before
                        # We toggle opposite based on what was previously stored

                        liked_obj = my_post_likes.get()
                        current_liked_val = liked_obj.liked
                        new_liked_val = None
                        liked_user_msg = None
                        if current_liked_val == "true":
                            new_liked_val = "false"
                            self.session["like_%s_status" % curr_post.key().id()] = "false"
                            liked_user_msg = "You just UN-LIKED Post: %s" % post_subject
                        else:
                            new_liked_val = "true"
                            self.session["like_%s_status" % curr_post.key().id()] = "true"
                            liked_user_msg = "LIKED Post: %s" % post_subject

                        liked_obj.liked = new_liked_val
                        key = liked_obj.put()

                        # Validate like for user still exists
                        like_check = Like.get(key)
                        print "Post LIKE check for USER returned: %s" % like_check.liked
                        
                        if like_check != None:
                            #print "Like Check for Like returned: %s" % like_check.liked
                            
                            # Set Messages and Redirect back to Welcome Home Page
                            # Display notice message saying Previously Liked Post already
                            self.clear_main_msg()
                            self.clear_msg_type()
                            self.set_main_msg(liked_user_msg)  
                            self.set_msg_type("notice")
                            
                            # Update session variables
                            self.session["messages_viewed"] = 0
                            self._set_jinja_variable_session()
                            self.redirect("/blog/welcome")
                else:
                    print "LIKING of POST instance failed!"
            # USER IS the OWNER of POST. So Can't LIKE
            else:
                print "*ERROR in LIKING post with logged in AND valid user*"
                # Display error message saying that you *must not be* the post Owner to LIKE
                self.clear_main_msg()
                self.clear_msg_type()
                self.set_main_msg("You can ONLY like other people's posts...")
                self.set_msg_type("error")
                
                # Update session variables
                self.session["messages_viewed"] = 0
                self._set_jinja_variable_session()

                self.redirect("/blog/welcome")

    def comment_post(self, post_id):
        print "IN: PostHandler().comment_post()"
        
        last_handler = None
        messages_viewed = 0
        try:
            last_handler = self.session.get("curr_handler")
            messages_viewed = self.session.get("messages_viewed")
        except:
            print "No Last Handler or Errors Viewed values exist"
        finally:
            self.session["curr_handler"] = "PostHandler"

        curr_post = Post.get_by_id(long(post_id))

        post_form_error = ""
        try:
            if self.session != None:
                if self.session.get('post_%s_form_error' % post_id) != None:
                    # Clear out Post Form Erorrs
                    self.clear_postform_errors(post_id)
            # Clear our Main MSG area
            self.clear_main_msg()
        except:
            print "Nothing exists in POST_FORM_ERROR value in session."

        print ("COMMENT Post received")

        # Check for logged in/valid user
        user_logged_in = False
        user_valid = False
        user_info = UserHandler().user_logged_in(self)
        user = None

        if user_info:
            user_logged_in = True
            user = UserHandler().user_loggedin_valid(self, user_info)
            if user:
                user_valid = True
            else:
                print "Cookie invalid @ PostHandler!"

        if user_logged_in == False or user_valid == False:
            print "Either NOT Logged In, or Not VALID..."
            # Clear existing session data (as not logged in)
            try:
                # Reset message for Clicked Post
                self.session["post_%s_form_error" % post_id] = "COMMENT requires Login!"

                # Set MAIN User MSG Text
                print "post subject is: %s" % curr_post.subject
                post_short_tag = "'%s...'" % curr_post.subject[0:20]
                self.set_main_msg("Please <a href='/blog/login'>Login</a> to COMMENT on post: %s" % post_short_tag)
                self.set_msg_type("error")
                
                print "After COMMENT click, session data is: %s" % self.session

                # Set error message to NOT viewed
                self.session["messages_viewed"] = 0

                #Update STORED Jinja global session variable (for use in templates)
                self._set_jinja_variable_session()

                # Redirect to LOGIN page
                self.redirect("/blog/login")
            except:
                print "Cannot add session variable in COMMENT Post"
        
            print "USER Not Logged in...for COMMENT"

        """
        COMMENT POST control for VALID and LOGGED IN User
        """
        if user_logged_in == True and user_valid == True:
            # Then we can proceed to COMMENT on post
            
            # Get User Messages to display if applicable
            #main_user_msgs = self.get_main_msg()
            #msg_type = self.get_msg_type()

            # Used in Notice to User below on successful comment
            #post_subject = curr_post.subject[:20]

            if curr_post != None:
                print "We are about to add a comment...."
                self.redirect("/blog/%s/comment" % post_id)
                #self.render("newcomment.html", comment_validation="", main_user_msgs=main_user_msgs, msg_type=msg_type, post=curr_post, post_subject=post_subject)

                #### LEft of here implementing COMMENTS 4/16/2017
            else:
                self.redirect("/blog/welcome")

    def clear_postform_errors(self, post_id):
        print "Clearing any PREVIOUSLY set post_form_error for Posts"

        posts = Post.all()
        for post in posts:
            try:
                print post.key().id()
                if post_id == post.key().id():
                    post_form_error = self.session.get('post_%s_form_error' % post.key().id())
                else:
                    self.session['post_%s_form_error' % post.key().id()] = ""
            except:
                print "FAILURE clearing Post Form Errors..."
            finally:
                self._set_jinja_variable_session()

        print "Exiting clear_postform_errors()"

    def set_post_likes(self, web_obj, posts, user):
        print "Setting any PREVIOUS Likes for Current User"

        for p in posts:
            try:
                post_like = user.user_likes.filter('post =', p).get()
                if post_like != None:
                    print ("Found a post liked on post")
                    if post_like.liked == "true":
                        print "post...liked is true"
                        web_obj.session["like_%s_status" % p.key().id()] = "true"
                    else:
                        print "post...liked is false"
                        web_obj.session["like_%s_status" % p.key().id()] = "false"
                else:
                    print post_like
            except:
                print "Error setting Post Likes for Current User..."
            finally:
                web_obj._set_jinja_variable_session()

        print "Finished setting LIKES on Posts for Current User."

    def style_postform_buttons(self, web_obj, posts, user):
        print "Styling post for buttons for the Current User"

        for p in posts:
            try:
                if p.created_by == user.username:
                    print "User is owner of Post...so updating session variables"
                    web_obj.session["post_%s_owner" % p.key().id()] = "true"
                else:
                    print "...this is someone else's post...."
                    web_obj.session["post_%s_owner" % p.key().id()] = "false"
            except: 
                print "Eror styling post form buttons by OWNER"
            finally:
                web_obj._set_jinja_variable_session()
                    
class PostCommentHandler(Handler):
    def add_new_comment(self, post, user, comment, parent=None):
        """
        As per our DB we will need: a) post instance, b) user instance, c) parent_ Comment instance,
        d) comment text body, and e) created_by (user instance user.username) to 
        create a new comment for the post
        """
        c = Comment(post=post, user=user, comment_parent=parent, comment=comment, created_by=user.username)
        key = c.put()

        # Do quick lookup of comment just put()
        new_comment = Comment.get(key)
        print "New comment is: %s" % new_comment
        
        # Update session to reflect this user as 'post-comment owner
        self.session["post_%s_comment_%s_owner" % (post.key().id(), c.key().id())] = "true"
        self._set_jinja_variable_session()

        # Redirect to blog post permalink page which displays comments
        self.redirect("/blog/%s" % post.key().id())

    def get(self, post_id, comment_id=None):
        print "IN: PostCommentHandler()"

        # Determine if we are viewing an existing comment or adding a new comment
        if post_id and comment_id != None:
            print "Post ID: %s, Comment ID: %s" % (post_id, comment_id)
        elif comment_id == None:
            print "Receiving a NEW Comment request for post: %s" % post_id

        curr_post = Post.get_by_id(long(post_id))
        # Used in Templates for new Comment below
        post_subject = curr_post.subject[:20]
        
        last_handler = None
        messages_viewed = 0
        try:
            last_handler = self.session.get("curr_handler")
            messages_viewed = self.session.get("messages_viewed")
        except:
            print "No Last Handler or Errors Viewed values exist"
        finally:
            self.session["curr_handler"] = "PostCommentHandler"

    
        # Refresh our stored Jinja inkpenbam session variable
        stored_jinja_session = self._get_jinja_variable_session()
        if stored_jinja_session == None:
            self._set_jinja_variable_session()
        
        # Get referrer source
        source = self.get_ref_source()
        if source != None:
            if messages_viewed == 1:
                # Clear any previous session messages to display clean page
                print "Previously displayed errors. So clearing..."
                self.clear_main_msg()

        # Get User Messages to display if applicable
        main_user_msgs = self.get_main_msg()
        msg_type = self.get_msg_type()

        # See if User is logged on, and if Not then Redirect to Signup Page
        user_logged_in = False
        user_valid = False
        user_info = UserHandler().user_logged_in(self)
        if user_info:
            # Some user cookie exists
            user_logged_in = True

            # Check validity of cookie info against DataStore
            user = UserHandler().user_loggedin_valid(self, user_info)

            if user:
                user_valid = True
                # Allow redirection to NEW Comment oage
                self.render("newcomment.html", comment_validation="", main_user_msgs=main_user_msgs,
                            msg_type=msg_type, post=curr_post, post_subject=post_subject)
            else:
                print "Cookie invalid @ PostCommentHandler!"

        # Mark any Error msgs as viewed if applicable
        if self.get_main_msg() != None and self.get_main_msg() != "":
            self.session["messages_viewed"] = 1
            self._set_jinja_variable_session()

        if user_logged_in == False or user_valid == False:
            self.set_main_msg("You need to <a href='/blog/login'>Login</a> to COMMENT on a post.")
            self.set_msg_type("error")
            self.session["messages_viewed"] = 0
            self._set_jinja_variable_session()
            self.redirect("/blog/login")

    def post_comment(self, web_obj, post_id):
        created_by = None
        user = None
        
        # Grab our logged in user info
        user_info = UserHandler().user_logged_in(web_obj)
        if user_info:
            user = UserHandler().user_loggedin_valid(web_obj, user_info)
            if user:
                created_by = user.username

        post_id = post_id
        post = Post.get_by_id(long(post_id))
        comment = web_obj.request.get("comment")

        comment_validation = ""

        validation_error = False

        if comment == "":
            # Create a validation error and msg
            comment_validation = "Comment text must be entered before submit..."
            validation_error = True

        main_user_msgs = None
        msg_type = None
        if validation_error == True:
            print "We have a validation error, so setting Main MSG"
            web_obj.clear_main_msg()
            web_obj.clear_msg_type()
            web_obj.set_main_msg("Comment values missing...")
            web_obj.set_msg_type("error")
            main_user_msgs = web_obj.get_main_msg()
            msg_type = web_obj.get_msg_type()

            # Update our session variable
            web_obj.session["messages_viewed"] = 1
            web_obj._set_jinja_variable_session()

        """
        If all OK add our Comment, else re-render page with error msg
        """
        if validation_error == False:
            web_obj.add_new_comment(post, user, comment)
        else:
            web_obj.render("newcomment.html", post=post, post_subject=post.subject[:20], 
                        comment=comment, comment_validation=comment_validation,
                        main_user_msgs=main_user_msgs, msg_type=msg_type)

    def post(self, post_id, comment_id=None):
        if comment_id == None:
            # We have a *initial* top level new COMMENT action
            print "Received an *initial* top level new comment request..."
            # Send to handler method
            self.post_comment(self, post_id)
        else:
            # We have an existing COMMENT action
            url_post_id = post_id
            url_comment_id = comment_id
            method = self.request.get("_method").upper()
            comment_id = self.request.get("comment_id")

            if url_comment_id == comment_id:
                print "Received a %s request for comment...." % method
                if method == "REPLY-FORM-REQUEST":
                    # This is a main reply REQUEST, not a direct REPLY action body submit
                    reply_body = None
                    initial_render = "true"
                    self.reply_comment(comment_id, post_id, reply_body, initial_render)
                elif method == "REPLY":
                    # Add a comment reply ACTION caller
                    # Pass REPLY text as posted
                    print "...in case...REPLY"
                    reply_body = self.request.get("reply")
                    self.reply_comment(comment_id, post_id, reply_body)
                elif method == "EDIT-FORM-REQUEST":
                    # This is a main comment edit REQUEST, not a direct edit action submit.
                    comment_body = None
                    initial_render = "true"
                    self.edit_comment(comment_id, comment_body, post_id, initial_render)
                elif method == "EDIT":
                    # Edit comment ACTION caller
                    # Pass COMMENT text as posted
                    print "...in case...EDIT"
                    comment_body = self.request.get("comment")
                    self.edit_comment(comment_id, comment_body, post_id)
                elif method == "DELETE":
                    # Delete our Comment right
                    print "...in case...DELETE"
                    self.delete_comment(comment_id, post_id)

                #redirect("/blog/welcome");
    
    def reply_comment(self, comment_id, post_id, reply_body, initial_render=None):
        print "IN: PostCommentHandler().reply_comment()"
        
        # OUR PARENT objects
        parent_comment = Comment.get_by_id(long(comment_id))
        parent_post = Post.get_by_id(long(post_id))
        
        last_handler = None
        messages_viewed = 0
        try:
            last_handler = self.session.get("curr_handler")
            messages_viewed = self.session.get("messages_viewed")
        except:
            print "No Last Handler or Errors Viewed values exist..."
        finally:
            self.session["curr_handler"] = "PostCommentHandler"

        # Refresh our stored jinja inkpenbam session variable
        stored_jinja_session = self._get_jinja_variable_session()
        if stored_jinja_session == None:
            self._set_jinja_variable_session()

        # Get referrer source
        source = self.get_ref_source()
        if source != None:
            if messages_viewed == 1:
                # Clear any previous session messages to display a clean page
                print "Previously displayed errors. So clearing..."
                self.clear_main_msg()

        # Get User MSGS to display
        main_user_msgs = self.get_main_msg()
        msg_type = self.get_msg_type()

        # Used for user output later
        post_subject = parent_post.subject[:20]

        # Check if user is logged in, and if not redirect to LOGIN
        user_logged_in = False
        user_valid = False
        user_info = UserHandler().user_logged_in(self)
        if user_info:
            # Some user cookie exists
            user_logged_in = True

            # Check validity of that user
            user = UserHandler().user_loggedin_valid(self, user_info)

            if user:
                user_valid = True
                # We have a logged on and valid user who can post a comment reply....
                # Set some default values
                reply_validation = ""
                validation_error = False
                main_user_msgs = ""
                msg_type = None
                
                if reply_body == None and initial_render == "true":
                    # We can just skip out initial form validation
                    print "Initial REPLY-FORM-REQUEST received..."
                    reply_body = ""
                else:
                    # Then our user is submitting an actual reply, from the form
                    # PEFORM some validation
                    if reply_body == "":
                        reply_validation = "Reply must contain REPLY text before submit..."
                        validation_error = True

                    if validation_error == True:
                        print "We have a validation error....Setting msg for our user..."
                        self.clear_main_msg()
                        self.clear_msg_type()
                        self.set_main_msg("Reply values are missing...")
                        self.set_msg_type("error")
                        main_user_msgs = self.get_main_msg()
                        msg_type = self.get_msg_type()

                        # Update session variables
                        self.session["messages_viewed"] = 1
                        self._set_jinja_variable_session()

                if reply_body == "" or validation_error == True:
                    # Render our Reply Form in either case
                    self.render("newcomment-reply.html", reply_validation=reply_validation, 
                                main_user_msgs=main_user_msgs, msg_type=msg_type, post=parent_post, 
                                comment=parent_comment, post_subject=post_subject, reply=reply_body)
                elif reply_body != "" and validation_error == False:
                    # Go ahead and create the reply....
                    print "ADDING THE REPLY to datastore"
                    c = Comment(post=parent_post, user=user, comment_parent=parent_comment, 
                                comment=reply_body, created_by=user.username)
                    key = c.put()

                    # Do a quick verify of add
                    new_reply = Comment.get(key)
                    print "New Reply is: %s" % new_reply

                    # Update session to reflect user as reply (i.e. a comment object) OWNER
                    self.session["post_%s_comment_%s_owner" % (parent_post.key().id(), c.key().id())] = "true"
                    self._set_jinja_variable_session()

                    # Redirect to blog post permalink page which displays all comments and replies
                    self.redirect("/blog/%s" % parent_post.key().id())
            else:
                print "Cookie invalide @ PostCommentHandler REPLY"

        # Mark any Error msgs as viewed if applicable
        if self.get_main_msg() != None and self.get_main_msg() != "":
            self.session["messages_viewed"] = 1
            self._set_jinja_variable_session()

        if user_logged_in == False or user_valid == False:
            self.set_main_msg("You need to <a href='/blog/login'>Login</a> to REPLY to a post comment.")
            self.set_msg_type("error")
            self.session["messages_viewed"] = 0
            self._set_jinja_variable_session()
            self.redirect("/blog/login")
    
    def edit_comment(self, comment_id, comment_body, post_id, initial_render=None):
        print "IN: PostCommentHandler().edit_comment()"
        self.session["curr_handler"] = "PostCommentHandler"

        curr_comment = Comment.get_by_id(long(comment_id))
        parent_post = Post.get_by_id(long(post_id))

        # Used for user output later
        post_subject = parent_post.subject[:20]

        comment_form_error = ""
        try:
            if self.session.get("post_%s_comment_%s_form_error" % (post_id, comment_id)) != None:
                # Clear our Comment Form Errors
                self.clear_commentform_errors(comment_id, post_id)
            # Clear our Main MSG area
            self.clear_main_msg()
        except:
            print "Nothing exists in COMMENT_FORM_ERROR value in session."

        print ("EDIT Comment received...")

        # Check fro logged in / valid user
        user_logged_in = False
        user_valid = False
        user_info = UserHandler().user_logged_in(self)
        user = None

        if user_info:
            user_logged_in = True
            user = UserHandler().user_loggedin_valid(self, user_info)
            if user: 
                user_valid = True
            else:
                print "Cookie invalid @ PostCommentHandler!"
        
        if user_logged_in == False and user_valid == False:
            print "Either NOT Logged In, or NOT Valid..."
            # set error message for user
            try:
                self.session["post_%s_comment_%s_form_error" % (post_id, comment_id)] = "MUST Login to EDIT a COMMENT!"
                self.set_main_msg("Please <a href='/blog/login'>Login</a> to EDIT COMMENT for post: '%s...'" 
                                    % post_subject)
                self.set_msg_type("error")
                self.session["messages_viewed"] = 0
                self._set_jinja_variable_session()
                self.redirect("/blog/login")
            except:
                print "Cannot add session variables for EDIT comment action"

            print "USER Not Logged In....for EDIT comment"

        if user_logged_in == True and user_valid == True:
            # Then we can delete this comment, if they are comment owner
            if curr_comment.created_by == user.username:
                print "User is OWNER of Comment. *CAN* Edit"
                # Comment Edit
                if curr_comment != None:
                    #EDIT COMMENT HERE
                    if comment_body == None or comment_body == "":
                        #Render our EditComment Page for comment editing
                        if (initial_render == "true"):
                            # Set our default form values to what is in datastore
                            comment_body = curr_comment.comment

                        comment_validation = ""
                        validation_error = False

                        if comment_body == "":
                            comment_validation = "Comment must contain TEXT body before submit..."
                            validation_error = True

                        main_user_msgs = ""
                        msg_type = None

                        if validation_error == True:
                            print "We have a validation error....So setting main message..."
                            self.clear_main_msg()
                            self.clear_msg_type()
                            self.set_main_msg("Edit COMMENT values missing...")
                            self.set_msg_type("error")
                            main_user_msgs = self.get_main_msg()
                            msg_type = self.get_msg_type()

                            # Update session variable
                            self.session["messages_viewed"] = 1
                            self._set_jinja_variable_session()

                        self.render("editcomment.html", post=parent_post, comment=curr_comment,
                                    comment_body=comment_body, comment_validation=comment_validation, 
                                    main_user_msgs=main_user_msgs, msg_type=msg_type)
                    else:
                        # Use the values from the request
                        print "Post comment body received...Performing Update..."
                        curr_comment.comment=comment_body
                        curr_comment.put()

                        # Check to make sure comment still exists
                        comment_check = Comment.get_by_id(long(comment_id))
                        print "Comment Check returned: %s" % comment_check

                        # Notify if we can't find Comment instance for some reason
                        if comment_check == None:
                            print "CANNOT find Comment instance!"
                        else:
                            print "SUCCESS Editing Comment instance!"
                            # display notices indicating success
                            self.clear_main_msg()
                            self.clear_msg_type()
                            self.set_main_msg('Success in editing COMMENT for Post: "%s"' % post_subject)
                            self.set_msg_type("notice")

                            # Update session variables
                            self.session["messages_viewed"] = 0
                            self._set_jinja_variable_session()

                        self.redirect("/blog/welcome")
            # USER is NOT OWNER of COMMENT. So can't EDIT
            else:
                print "*ERROR in EDITING comment instance with logged in and valid user...*"
                # Display error message indicating they need to be comment owner to delete
                self.clear_main_msg()
                self.clear_msg_type()
                self.set_main_msg("You can ONLY edit your own comments...")
                self.set_msg_type("error")

                # Update session variables
                self.session["messages_viewed"] = 0
                self._set_jinja_variable_session()

                self.redirect("/blog/welcome")
    
    def delete_comment(self, comment_id, post_id):
        print "IN: PostCommentHandler().delete_comment()"
        self.session["curr_handler"] = "PostCommentHandler"

        curr_comment = Comment.get_by_id(long(comment_id))
        parent_post = Post.get_by_id(long(post_id))

        # Used for user output later
        post_subject = parent_post.subject[:20]

        comment_form_error = ""
        try:
            if self.session.get("post_%s_comment_%s_form_error" % (post_id, comment_id)) != None:
                # Clear our Comment Form Errors
                self.clear_commentform_errors(comment_id, post_id)
            # Clear our Main MSG area
            self.clear_main_msg()
        except:
            print "Nothing exists in COMMENT_FORM_ERROR value in session."

        print ("DELETE Comment received...")

        # Check fro logged in / valid user
        user_logged_in = False
        user_valid = False
        user_info = UserHandler().user_logged_in(self)
        user = None

        if user_info:
            user_logged_in = True
            user = UserHandler().user_loggedin_valid(self, user_info)
            if user: 
                user_valid = True
            else:
                print "Cookie invalid @ PostCommentHandler!"
        
        if user_logged_in == False and user_valid == False:
            print "Either NOT Logged In, or NOT Valid..."
            # set error message for user
            try:
                self.session["post_%s_comment_%s_form_error" % (post_id, comment_id)] = "DELETE requires Login!"
                self.set_main_msg("Please <a href='/blog/login'>Login</a> to DELETE comment for post: '%s...'" 
                                    % post_subject)
                self.set_msg_type("error")
                self.session["messages_viewed"] = 0
                self._set_jinja_variable_session()
                self.redirect("/blog/login")
            except:
                print "Cannot add session variables for DELETE comment action"

            print "USER Not Logged In....for DELETE comment"

        if user_logged_in == True and user_valid == True:
            # Then we can delete this comment, if they are comment owner
            if curr_comment.created_by == user.username:
                print "User is OWNER of Comment. *CAN* Delete"
                # Comment Deletion
                if curr_comment != None:
                    try:
                        def del_curr_comment(c):
                            if c.replies.count() == 0:
                                print "in case no children"
                                c.delete()
                            else:
                                for c_child in c.replies:
                                    print "in case child"
                                    del_curr_comment(c_child)

                                # Delete the child
                                c_child.delete()
                                # Delete the master parent, 'curr_comment'
                                c.delete()
                                    
                        # Call recursive delete on current comment entity
                        del_curr_comment(curr_comment)
                    except:
                        print "Error deleteing comments and associated replies...."
                    finally:
                        print "Done handling comment delete...submitting output of result."

                # Check to make sure comment is delete
                comment_check = Comment.get_by_id(long(comment_id))
                print "Comment Check returned: %s" % comment_check

                # Redirect if Comment instance deleted successfully
                if comment_check == None:
                    # Clear any messages
                    self.clear_main_msg()
                    self.clear_msg_type()
                    # Set success msg
                    self.set_main_msg('Success in deleting COMMENT for Post: "%s"' % post_subject)
                    self.set_msg_type("notice")

                    # Update session variable
                    del self.session["post_%s_comment_%s_owner" % (post_id, comment_id)]
                    self.session["messages_viewed"] = 0
                    self._set_jinja_variable_session()
                    self.redirect("/blog/welcome")
                else:
                    print "DELETE of COMMENT instance failed!"
            #USER is NOT Owner of COMMENT here. So Can't DELETE
            else:
                print "*ERROR in DELETING comment instance with logged in and valid user...*"
                # Display error message indicating they need to be comment owner to delete
                self.clear_main_msg()
                self.clear_msg_type()
                self.set_main_msg("You can ONLY delete your own comments...")
                self.set_msg_type("error")

                # Update session variables
                self.session["messages_viewed"] = 0
                self._set_jinja_variable_session()

                self.redirect("/blog/welcome")

    def clear_commentform_errors(self, comment_id, post_id):
        print "Clearing any PREVIOUSLY set comment_form_error for Comments"

        comments = Comment.all()
        for comment in comments:
            try:
                if comment_id == comment.key().id():
                    comment_form_error = self.session.get("post_%s_comment_%s_form_error" % (post_id, comment_id))
                else:
                    self.session["post_%s_comment_%s_form_error" % (post_id, comment_id)] = ""
            except:
                print "FAILURE clearing Comment Form Errors..."
            finally:
                self._set_jinja_variable_session()

        print "Exiting clear_commentform_errors()"

    def style_commentform_buttons(self, web_obj, post, user):
        print "Styling comment buttons for the current user..."
        print post.subject

        for c in post.post_comments:
            try:
                if c.created_by == user.username:
                    print "User is owner of Comment...so updating session variables"
                    web_obj.session["post_%s_comment_%s_owner" % (post.key().id(), c.key().id())] = "true"
                else:
                    print "...this is someone else's comment..."
                    web_obj.session["post_%s_comment_%s_owner" % (post.key().id(), c.key().id())] = "false"
            except:
                print "Error styling comment button on posts by OWNER"
            finally:
                web_obj._set_jinja_variable_session()

"""
NEW Post URL Handler, for our blog post additions
"""
class NewPost(Handler):
    def add_new_post(self, subject, content, created_by):
        p = Post(subject=subject, content=content, created_by=created_by)
        p.put() 

        # Update session to reflect this user as post owner
        self.session["post_%s_owner" % p.key().id()] = "true"
        self._set_jinja_variable_session()

        #print p
        self.redirect("/blog/%s" % p.key().id())

    def get(self):
        print "IN: NewPost.Handler()"

        last_handler = None
        messages_viewed = 0
        try:
            last_handler = self.session.get("curr_handler")
            messages_viewed = self.session.get("messages_viewed")
        except:
            print "No Last Handler or Errors Viewed values exist"
        finally:
            self.session["curr_handler"] = "NewPost"

        # Refresh our stored Jinja inkpenbam_session variable
        stored_jinja_session = self._get_jinja_variable_session()
        if stored_jinja_session == None:
            self._set_jinja_variable_session()

        # Get referrer source
        source = self.get_ref_source()

        if source != None:
            if messages_viewed == 1:
                # Clear our previous session messages to display clean page
                print "Previously displayed errors. So clearing..."
                self.clear_main_msg()

        # Get User Messages to display if applicable
        main_user_msgs = self.get_main_msg()
        msg_type = self.get_msg_type()

        # See if User is logged on, if Not then Redirect to Signup Page
        user_logged_in = False
        user_valid = False
        user_info = UserHandler().user_logged_in(self)

        if user_info:
            # Some user cookie exists
            user_logged_in = True

            # Check validity of cookie info against DataStore
            user = UserHandler().user_loggedin_valid(self, user_info)

            if user:
                user_valid = True
                # Allow redirection to NEW Post page
                self.render("newpost.html", subject_validation="", content_validation="", main_user_msgs=main_user_msgs, msg_type=msg_type)
            else:
                print "Cookie invalid @ NewPost handler!"

        # Mark any Error msgs as viewed if applicable
        if self.get_main_msg != None and self.get_main_msg != "":
            self.session["messages_viewed"] = 1
            self._set_jinja_variable_session()

        if user_logged_in == False or user_valid == False:
            #self.redirect("/blog/signup") # redirecting to login instead
            self.set_main_msg("You need to <a href='/blog/login'>Login</a> to ADD a post.")
            self.set_msg_type("error")
            self.session["messages_viewed"] = 0
            self._set_jinja_variable_session()
            self.redirect("/blog/login")

    def post(self):
        created_by = None

        # Grab User Info
        user_info = UserHandler().user_logged_in(self)
        if user_info:
            user = UserHandler().user_loggedin_valid(self, user_info)
            if user:
                created_by = user.username

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
        
        main_user_msgs = None
        msg_type = None
        #Check if we have a validation error. If so, set msg to client
        if validation_error == True:
            print "We have a validation error....setting Main Msg for user..."
            self.clear_main_msg()
            self.clear_msg_type()
            self.set_main_msg("Post values missing...")
            self.set_msg_type("error")
            main_user_msgs = self.get_main_msg()
            msg_type = self.get_msg_type()

            #Update session variables
            self.session["messages_viewed"] = 1
            self._set_jinja_variable_session()

        """
        If all is well, add the post...Otherwise render the page with errors
        """
        if validation_error == False:
            self.add_new_post(subject, content, created_by)
        else:
            self.render("newpost.html", subject=subject, content=content, 
                        subject_validation=subject_validation, content_validation=content_validation,
                        main_user_msgs=main_user_msgs, msg_type=msg_type)

""" 
Main BLOG Front Page Handler
"""
class Blog(Handler):
    def get(self):
        print "IN: Blog.Handler()"
        
        last_handler = None
        messages_viewed = 0
        try:
            last_handler = self.session.get("curr_handler")
            messages_viewed = self.session.get("messages_viewed")
        except:
            print "No Last Handler or Errors Viewed values exist"
        finally:
            self.session["curr_handler"] = "Blog"

        # Convenience stored Jinja session global for potential use in templates
        stored_jinja_session = self._get_jinja_variable_session()
        if stored_jinja_session == None:
            stored_jinja_session = self._set_jinja_variable_session()

        # Check Referrer to display appropriate Errors and Messages
        source = self.get_ref_source()

        if source != None:
            if messages_viewed == 1:
                # Clear our previous session messages to display clean page
                print "Previously display errors. So clearing...."
                self.clear_main_msg()

        #my_session = self.session
        main_user_msgs = self.get_main_msg()
        msg_type = self.get_msg_type()

        print "My Jinja stored session details after get/set _session are: %s" % stored_jinja_session
        print "Comparing... LIVE session: %s" % self.session

        posts_exist = False
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
        # Output post.ids for debugging
        #for post in posts: 
        #    print post.key().id()

        if posts.get() != None:
            print "We have Posts"
            posts_exist = True

            if source!= None:
                if messages_viewed == 1:
                    #Clear out previous Individual Post Error messages
                    print "Previous post errors exist... Cleaning up..."
                
                    for p in posts:
                        try:
                            self.session['post_%s_form_error' % p.key().id()] = ""
                            # Update session to reflect logged out, and therefore not post owner
                            self.session["post_%s_owner" % p.key().id()] = ""
                            try:
                                print "Post has %s comments... Clearing errors..." % p.post_comments.count()
                                for c in p.post_comments:
                                    # Do the same for comments
                                    self.session["post_%s_comment_%s_form_error" % (p.key().id(), c.key().id())] = "" 
                                    self.session["post_%s_comment_%s_owner" % (p.key().id(), c.key().id())] = ""
                            except:
                                print "Cannot blank individual comment post session error..."
                        except:
                            print "Cannot blank individual post session error..."
                        finally:
                            self._set_jinja_variable_session()

            # Render our page
            self.render("blog.html", posts=posts, curr_session=stored_jinja_session, main_user_msgs=main_user_msgs, msg_type=msg_type)

        # Redirect as necessary if we have a Valid User Logged In
        user_logged_in = False
        user_valid = False
        user_info = UserHandler().user_logged_in(self)

        if user_info:
            user_logged_in = True
            user = UserHandler().user_loggedin_valid(self, user_info)

            if user:
                print ("We have a USER that is logged in @ '/blog' FRONT")
                user_valid = True
                self.redirect("/blog/welcome")

        # If NO user posts yet exist, And NO User logged in...just redirect to SIGNUP page
        if (user_logged_in == False or user_valid == False) and posts_exist == False:
            self.redirect("/blog/signup")

        # Mark any Error msgs as viewed if applicable
        if self.get_main_msg != None and self.get_main_msg != "":
            self.session["messages_viewed"] = 1
            self._set_jinja_variable_session()

    # Unused
    def post(self):
        self.render("blog.html")

        
class Welcome(Handler):
    def get(self):
        print "IN: Welcome.Handler()"

        last_handler = None
        messages_viewed = None
        login_msg_displayed_once = None    # So first time welcome loaded this session
        try:
            last_handler = self.session.get("curr_handler")
            messages_viewed = self.session.get("messages_viewed")
            login_msg_displayed_once = self.session.get("login_msg_displayed_once")
        except:
            print "No Last Handler or Errors Viewed values exist"
        finally:
            self.session["curr_handler"] = "Welcome"

        # Refresh our stores Jinja inkpenbam session variabl
        stored_jinja_session = self._get_jinja_variable_session()
        if stored_jinja_session == None:
            self._set_jinja_variable_session()

        # Get referrer source
        source = self.get_ref_source()

        if source != None:
            if messages_viewed == 1:
                # Clear our previous session messages to display a clean page
                print "Previously displayed messages. So clearing..."
                self.clear_main_msg()

        # Get User Messages to display, if applicable
        main_user_msgs = self.get_main_msg()
        msg_type = self.get_msg_type()

        # For Tabbed Content on Welcome page, Default is None
        all_posts = None
        user_logged_posts = None

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

                # Get All Posts BY USER
                user_logged_posts = db.GqlQuery("SELECT * FROM Post WHERE created_by = :created_by ORDER BY created DESC", created_by=username)

                if user_logged_posts.get() == None and login_msg_displayed_once == None:
                    print "No User POSTS exist...."
                    self.set_main_msg("Hmm...you have 0 posts. Please <a href='/blog/newpost'>add some</a>. :)")
                    main_user_msgs = self.get_main_msg()
                    msg_type = self.set_msg_type("notice")
                    self.session["messages_viewed"] = 0
                    self.session["login_msg_displayed_once"] = 1
                else:
                    self.clear_main_msg()
                    self.clear_msg_type()

                # Ensure jinja session variables are in-sync
                self._set_jinja_variable_session()

                all_posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
                if all_posts.get() != None:
                    # Get ALL the POSTS and set All Post *initial like* values if
                    # this is the first time viewing welcome page after login
                    #if login_msg_displayed_once == None:
                    # Set any Post LIKEs for Current Logged in and Valid User
                    PostHandler().set_post_likes(self, all_posts, user)
                    # Style Post Form buttons for current user
                    PostHandler().style_postform_buttons(self, all_posts, user)
                
                for post in all_posts:
                    if post.post_comments.get() != None:
                        # Style Comment Form buttons for current user
                        PostCommentHandler().style_commentform_buttons(self, post, user)

                #print "BEFORE render, main_user_msgs is: %s" % main_user_msgs 
                # Get Current Date Time
                current_date_time = datetime.datetime.utcnow()
                
                # Render our page
                self.render("welcome.html", username=username, user_logged_posts=user_logged_posts, 
                            all_posts=all_posts, main_user_msgs=main_user_msgs, msg_type=msg_type, 
                            current_date_time=current_date_time)
        else:
            print "We don't have a cookie set yet!"

        # Mark any Error msgs as viewed if applicable
        if self.get_main_msg != None and self.get_main_msg != "":
            self.session["messages_viewed"] = 1
            self._set_jinja_variable_session()
            
        # Redirect to signup page if USER is invalid or NOT Logged in
        if user_logged_in == False or user_valid == False:
            self.redirect("/blog/signup")
    
class Login(Handler):
    def get(self):
        print "IN: Login.Handler()"

        # 1st Check if User Logged on AND Valid. If so, redirect to /blog/welcome
        user_logged_in = False
        user_valid = False
        user_info = UserHandler().user_logged_in(self)

        if user_info:
            user_logged_in = True
            user = UserHandler().user_loggedin_valid(self, user_info)

            if user:
                print ("We have a USER that is LOGGED In and Valid")
                user_valid = True
                self.redirect("/blog/welcome")
        
        last_handler = None
        messages_viewed = 0
        try:
            last_handler = self.session.get("curr_handler")
            messages_viewed = self.session.get("messages_viewed")
        except:
            print "No Last Handler or Errors Viewed values exist"
        finally:
            self.session["curr_handler"] = "Login"
        
        # Refresh our stored Jinja inkpenbam_session variable
        stored_jinja_session = self._get_jinja_variable_session()
        if stored_jinja_session == None:
            self._set_jinja_variable_session()

        # Get referrer source
        source = self.get_ref_source()

        if source!= None:
            if messages_viewed == 1:
                # Clear our previous session messages to display clean page
                print "Previously displayed errors. So clearing..."
                self.clear_main_msg()

        # Get User Messages for display, if applicable
        main_user_msgs = self.get_main_msg()
        msg_type = self.get_msg_type()
        
        self.render("login.html", validation_error="", main_user_msgs=main_user_msgs, msg_type=msg_type)

        # Mark any Error msgs as viewed if applicable
        if self.get_main_msg != None and self.get_main_msg != "":
            self.session["messages_viewed"] = 1
            self._set_jinja_variable_session()

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        
        # Error MSG we render on out html page
        login_error = "Invalid Login"   
        
        # Becomes True if error is found
        validation_error = False

        last_handler = None
        messages_viewed = 0
        try:
            last_handler = self.session.get("curr_handler")
            messages_viewed = self.session.get("messages_viewed")
        except:
            print "No Last Handler or Errors Viewed values exist"
        finally:
            self.session["curr_handler"] = "Login"
        
        # Refresh our stored Jinja inkpenbam_session variable
        stored_jinja_session = self._get_jinja_variable_session()
        if stored_jinja_session == None:
            self._set_jinja_variable_session()
        # 1st Check if User entered exists 
        user = UserHandler().user_exists(username)
        if user != None:
            #print "User exists in our DataStore...."
            # User matches a User in DataStore
            # 2nd Check if Password entered was correct
            if UserHandler().user_verify_pass(user, password):
                print "Password matches our DataStore...."
                if UserHandler().set_cookie(self, user):
                    # Let's cleanup all error messages before directing to Welcome Page
                    posts_exist = False
                    posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
                    if posts.get() != None:
                        posts_exist = True
                        source = self.get_ref_source()
                        if source!= None:
                            if messages_viewed == 1:
                                print "Cleaning...house...."
                                for p in posts:
                                    try:
                                        self.session['post_%s_form_error' % p.key().id()] = ""
                                    except:
                                        print "Cannot blank individual post error msg..."
                                    finally:
                                        self._set_jinja_variable_session()

                    # SEND OFF to Our LOGGED in Welcome Page
                    self.redirect("/blog/welcome")
                else:
                    print "Problem setting cookie..."
            else:
                validation_error = True
        else:
            validation_error = True
        
        main_user_msgs = None
        msg_type = None
        #Check if we have a validation error. If so, set msg to client
        if validation_error == True:
            print "We have a validation error....setting Main Msg for user..."
            self.clear_main_msg()
            self.clear_msg_type()
            self.set_main_msg("Login Error. Please check credentials...")
            self.set_msg_type("error")
            main_user_msgs = self.get_main_msg()
            msg_type = self.get_msg_type()

            #Update session variables
            self.session["messages_viewed"] = 1
            self._set_jinja_variable_session()

        self.render("login.html", login_error=login_error, main_user_msgs=main_user_msgs, msg_type=msg_type)

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
LIKE GAE Entity (Model) for persistance
"""
class Like(db.Model):
    # 'likes' Collection, as we can have MANY likes for 1 post
    post = db.ReferenceProperty(Post, 
                                collection_name='post_likes')

    # likewise, we can have MANY likes for 1 user
    user = db.ReferenceProperty(User,
                                collection_name='user_likes')

    liked = db.StringProperty(choices=('true', 'false'), required = True) 
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

"""
COMMENT GoogleAppEngine (Model) for persistance
"""
class Comment(db.Model):
    post = db.ReferenceProperty(Post,
                                collection_name='post_comments')

    user = db.ReferenceProperty(User,
                                collection_name='user_comments')

    comment_parent = db.SelfReferenceProperty(required=False, default=None,
                                collection_name='replies')

    comment = db.TextProperty(required = True)
    created_by = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self, post):
        self._render_content = self.comment.replace('\n', '<br />')
        return Handler().render_str("comment.html", comment=self, post=post)

    def render_single(self):
        single_content = self.comment.replace('\n', '<br />')
        self._render_single = single_content
        return Handler().render_str("comment-single-reply.html", comment=self)

"""
Catch-All Blog Router
"""
class BlogRouter(Handler):
    def get(self):
        self.redirect("/blog")

SECRET_KEY = Hasher().get_secret_key()

config = {}
config['webapp2_extras.sessions'] = {
    'secret_key': '%s' % SECRET_KEY,
}
config['TEMPLATES_AUTO_RELOAD'] = True

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
    webapp2.Route(r'/blog/<post_id:\d+>/comment', handler=PostCommentHandler, name='newcomment'),
    webapp2.Route(r'/blog/<post_id:\d+>/comment/<comment_id:\d+>', handler=PostCommentHandler, name='comment')
], config=config, debug=True)
