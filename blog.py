# Nathan D Hernandez
# Udacity - FullStack Nano Degree
#
# Intro To Backend - Ink-Pen-Bam! blog App
import os
import string
import re
import datetime
import hashlib
import random
import webapp2

# Google App Engine DataStore
from google.appengine.ext import db

# webapp2 simple sessions
from webapp2_extras import sessions

# data Models for Ink-Pen-Bam (ipb) app
from ipbmodels import User, Post, Like, Comment

# note: ipbbase also contains 'template_dir' and 'jinja_env'
# definitions
from ipbbase import Handler


"""
Security/Authentication Section:
--Secure Hashing,
--Signup
--Login/Logout
--UserHandler:
    *Helper functions for base user control:
        --setting cookies, checking stored
        --info for our user, etc...
--Authenticator:
    *Handles main logic to check whether a
     user is BOTH logged in and VALID
"""


class Hasher:
    """
    HASHING SPECIFIC 'secret key' stored in top directory file 'inkpenbam.key'
    """
    def get_secret_key(self):
        # Secret Key to make more secure password hash.
        # This is the same generated key as used in the
        # CONFIG variable for sessions
        secret_key = None
        try:
            keyfile = os.path.join(os.path.dirname(__file__), 'inkpenbam.key')
            if os.path.exists(keyfile):
                print "KEY_FILE exists....extracting SECRET_KEY..."
                file_handler = open(keyfile)
                secret_key = file_handler.read().strip()
                # print secret_key
            else:
                print "******MISSING KEY_FILE***********"
        except IOError:
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
        q = db.GqlQuery("SELECT * FROM User WHERE username = :username",
                        username=username)
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
    def make_pw_hash(self, name, pw, salt=None):
        SECRET_KEY = self.get_secret_key()
        if salt is None:
            salt = self.make_salt()
        return "%s|%s" % (self.hash_str(name + pw + SECRET_KEY + salt), salt)

    """
    Checks against stored data, to see if PW submitted = Stored Hash PW
    """
    def check_pw_hash(self, user_obj, submitted_password):
        # print "Submitted Password Received: %s" % submitted_password
        # print "User Obj Received: %s" % str(user_obj)
        pass_hash = self.make_pw_hash(user_obj.username, submitted_password,
                                      user_obj.salt).split('|')

        if pass_hash is not None and pass_hash[0] == user_obj.password:
            return True
    """
    END HASHING SPECIFIC
    """


class UserSignup(Handler):
    def get(self):
        print "IN: UserSignup.Handler()"

        # 1st Check if User Logged on AND Valid.
        # If so, redirect to /blog/welcome
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
        except LookupError:
            print "No Last Handler or Errors Viewed values exist"
        finally:
            self.session["curr_handler"] = "UserSignup"

        # Refresh our stored Jinja inkpenbam_session variable
        stored_jinja_session = self._get_jinja_variable_session()
        if stored_jinja_session is None:
            self._set_jinja_variable_session()

        # Get referrer souce
        source = self.get_ref_source()

        if source is not None:
            if messages_viewed == 1:
                # Clear our previous session messages to display clean page
                print "Previously displayed errors. So clearing..."
                self.clear_main_msg()

        # Get User Messages for display, if applicable
        main_user_msgs = self.get_main_msg()
        msg_type = self.get_msg_type()

        self.render("user-signup.html", username_validation="",
                    password_validation="", verify_validation="",
                    email_validation="", main_user_msgs=main_user_msgs,
                    msg_type=msg_type)

        # Mark any Error msgs as viewed if applicable
        if self.get_main_msg is not None and self.get_main_msg is not "":
            self.session['messages_viewed'] = 1
            self._set_jinja_variable_session()

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        # print username

        user_validation = ""
        pass_validation = ""
        pass2_validation = ""
        mail_validation = ""

        validation_error = False

        # print self.valid_username(username)
        if UserHandler().valid_username(username) is None:
            user_validation = "That's not a valid username."
            validation_error = True
        if username:
            if UserHandler().user_exists(username) is not None:
                user_validation = ("""Username already exists,
                                   please choose another!""")
                validation_error = True
        if UserHandler().valid_password(password) is None:
            pass_validation = "That wasn't a valid password."
            validation_error = True
        if UserHandler().valid_password(password) is not None:
            if verify is not None and verify != password:
                    pass2_validation = "Your passwords didn't match."
                    validation_error = True
        if email != "":
            if UserHandler().valid_email(email) is None:
                mail_validation = "That's not a valid email."
                validation_error = True

        main_user_msgs = None
        msg_type = None
        # Check if we have a validation error. If so, set msg to client
        if validation_error is True:
            print "We have a validation error....setting Main Msg for user..."
            self.clear_main_msg()
            self.clear_msg_type()
            self.set_main_msg("Signup Error(s) exist. Please check...")
            self.set_msg_type("error")
            main_user_msgs = self.get_main_msg()
            msg_type = self.get_msg_type()

            # Update session variables
            self.session["messages_viewed"] = 1
            self._set_jinja_variable_session()

        self.render("user-signup.html", username=username, email=email,
                    username_validation=user_validation,
                    password_validation=pass_validation,
                    verify_validation=pass2_validation,
                    email_validation=mail_validation,
                    main_user_msgs=main_user_msgs, msg_type=msg_type)

        if validation_error is False:
            user = UserHandler().create_user(username, password, email)
            if user is not None:
                # Set our User Cookie
                UserHandler().set_cookie(self, user)
            else:
                print ("USER not created ERROR!")

            # Redirect to Welcome, as validation_error is False
            self.redirect("/blog/welcome")


class Login(Handler):
    def get(self):
        print "IN: Login.Handler()"

        # 1st Check if User Logged on AND Valid.
        # If so, redirect to /blog/welcome
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
        except LookupError:
            print "No Last Handler or Errors Viewed values exist"
        finally:
            self.session["curr_handler"] = "Login"

        # Refresh our stored Jinja inkpenbam_session variable
        stored_jinja_session = self._get_jinja_variable_session()
        if stored_jinja_session is None:
            self._set_jinja_variable_session()

        # Get referrer source
        source = self.get_ref_source()

        if source is not None:
            if messages_viewed == 1:
                # Clear our previous session messages to display clean page
                print "Previously displayed errors. So clearing..."
                self.clear_main_msg()

        # Get User Messages for display, if applicable
        main_user_msgs = self.get_main_msg()
        msg_type = self.get_msg_type()

        self.render("login.html", validation_error="",
                    main_user_msgs=main_user_msgs, msg_type=msg_type)

        # Mark any Error msgs as viewed if applicable
        if self.get_main_msg is not None and self.get_main_msg != "":
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
        except LookupError:
            print "No Last Handler or Errors Viewed values exist"
        finally:
            self.session["curr_handler"] = "Login"

        # Refresh our stored Jinja inkpenbam_session variable
        stored_jinja_session = self._get_jinja_variable_session()
        if stored_jinja_session is None:
            self._set_jinja_variable_session()
        # 1st Check if User entered exists
        user = UserHandler().user_exists(username)
        if user is not None:
            # print "User exists in our DataStore...."
            # User matches a User in DataStore
            # 2nd Check if Password entered was correct
            if UserHandler().user_verify_pass(user, password):
                print "Password matches our DataStore...."
                if UserHandler().set_cookie(self, user):
                    # Let's cleanup all error messages before
                    # directing to Welcome Page
                    posts_exist = False
                    posts = db.GqlQuery("""SELECT * FROM Post ORDER BY
                                        created DESC""")
                    if posts.get() is not None:
                        posts_exist = True
                        source = self.get_ref_source()
                        if source is not None:
                            if messages_viewed == 1:
                                print "Cleaning...house...."
                                for p in posts:
                                    try:
                                        self.session['post_%s_form_error' %
                                                     p.key().id()] = ""
                                    except LookupError:
                                        print ("""Cannot blank individual
                                               post error msg...""")
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
        # Check if we have a validation error. If so, set msg to client
        if validation_error is True:
            print "We have a validation error....setting Main Msg for user..."
            self.clear_main_msg()
            self.clear_msg_type()
            self.set_main_msg("Login Error. Please check credentials...")
            self.set_msg_type("error")
            main_user_msgs = self.get_main_msg()
            msg_type = self.get_msg_type()

            # Update session variables
            self.session["messages_viewed"] = 1
            self._set_jinja_variable_session()

        self.render("login.html", login_error=login_error,
                    main_user_msgs=main_user_msgs, msg_type=msg_type)


class Logout(Handler):
    def get(self):
        user_info = self.request.cookies.get('user_id')

        if user_info is not None:
            user_info = user_info.split('|')
            user_id = user_info[0]

            # Grab our User
            user = UserHandler().user_exists(user_id)
            if user:
                # Delete our Cookie
                UserHandler().delete_cookie(self, user)

        # Redirect to Signup page
        self.redirect("/blog/signup")


class UserHandler:
    """
    Handles the Main USER operations
    """
    def create_user(self, username, password, email=None):
        hashed_pass = Hasher().make_pw_hash(username, password).split('|')
        if hashed_pass:
            my_pass = hashed_pass[0]
            my_salt = hashed_pass[1]
            user = User(username=username, password=my_pass,
                        email=email, salt=my_salt)
            key = user.put()
            my_user = User.get(key)
        return my_user

    # Cookie Related functions
    def check_cookie(self, web_obj, user):
        user_cookie = web_obj.request.cookies.get('user_id')
        print user_cookie

    def set_cookie(self, web_obj, user):
        cookie_data = "%s|%s" % (str(user.username), str(user.password))
        web_obj.response.headers.add_header('Set-Cookie', 'user_id=%s; path=/;'
                                            % cookie_data)

        # Duplicate this data in 'session' cookie
        # for testing webapp2 simple sessions
        web_obj.session['username'] = user.username
        # Set some additional DEFAULT 'session' cookie variables
        # web_obj.session['post_5901353784180736_form_error'] = "Test"

        # Additionally set Jinja Global Environment
        # to contain session data, If Not YET Set
        my_session = None
        jinja_env = Handler()._get_jinja_env()
        try:
            my_session = jinja_env.globals.get('inkpenbam_session')
        except LookupError:
            jinja_env.globals['inkpenbam_session'] = web_obj.session

        if cookie_data is not None:
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

            if user_id is not None and hashed_pass is not None:
                user_logged_in = True
                return user_info
            else:
                print "No User Logged in...."
        else:
            print "No User Logged in...."

        if user_logged_in is False:
            return None

    def user_loggedin_valid(self, web_obj, user_info):
        user_valid = False

        if user_info:
            user_id = user_info[0]
            hashed_pass = user_info[1]

            # First use UserSignup function to see if user exists
            user = self.user_exists(user_id)
            if user:
                # Next validate hashed_pass matches what is DB
                if user.password == hashed_pass:
                    user_valid = True
            else:
                print "Invalid User and Cookie set"

        if user_valid is True:
            return user

    # Checks whether a user exists in the DataStore
    def user_exists(self, username):
        # Check if USER already exists in DataStore
        q = db.GqlQuery("SELECT * FROM User WHERE username = :username",
                        username=username)
        # Get the 1st record result
        user = q.get()
        # print "in User exists %s" % user
        # print User.all().get().username
        return user

    # Verifies User entered Password on Forms
    # matches what we expect from DataStore
    def user_verify_pass(self, user_obj, submitted_password):
        # Validate against Hasher().check_pw_hash function
        if Hasher().check_pw_hash(user_obj, submitted_password):
            return True


class Authenticator:
    def __init__(self, web_obj):
        self.web_obj = web_obj

    def authenticate(self):
        # Check for logged in / valid user
        user = None
        user_logged_in = False
        user_valid = False
        result = {}

        # UserHandler object for check
        user_handler = UserHandler()
        user_info = user_handler.user_logged_in(self.web_obj)

        if user_info:
            # We have some logged in user
            user_logged_in = True
            # Grab user object
            user = user_handler.user_loggedin_valid(self.web_obj, user_info)

        if user:
            # We have BOTH a logged in and VALID user
            user_valid = True
        else:
            print "Cookie invalid @ Authenticator for: %s!" % self.web_obj

        result = {'user_logged_in': user_logged_in, 'user_valid': user_valid,
                  'user': user}

        return result


"""
Entity/Action specific Handlers:
--NewPostHandler:
    *Endpoint handler for new
    *initial posts to blog
--PostHandler:
    *get/post main point of Entry
    *for remaining operations of:
        --Delete, Edit, Like,
        --and Commenting
--DeletePostHandler:
    *controls DELETE activity on a Post
--EditPostHandler:
    *controls EDIT activity on a Post
--LikePostHandler:
    *controls LIKE activity on a Post
--PostCommentHandler:
    *controls initial COMMENT activity
    *on a Post
#####################################
"""


class NewPostHandler(Handler):
    """
    NEW Post URL Handler, for our *initial* blog post additions
    """
    def __add_new_post(self, subject, content, created_by):
        """
        No need for user login check/validation here
        as this function is only called through other endpoints.
        i.e. it isn't accessible through own endpoint
        Existing endpoints already check authencation before this point.
        In any event, if created_by=None, it would mean we couldn't
        add the post.
        """
        # User at this point would be VALID and IS LOGGED IN
        # We can proceed to add our NEW post
        if created_by:
            p = Post(subject=subject, content=content, created_by=created_by)
            p.put()

            # Update session to reflect this user as post owner
            self.session["post_%s_owner" % p.key().id()] = "true"
            self._set_jinja_variable_session()

            # print p
            self.redirect("/blog/%s" % p.key().id())

    def get(self):
        print "IN: NewPostHandler.Handler()"

        last_handler = None
        messages_viewed = 0
        try:
            last_handler = self.session.get("curr_handler")
            messages_viewed = self.session.get("messages_viewed")
        except LookupError:
            print "No Last Handler or Errors Viewed values exist"
        finally:
            self.session["curr_handler"] = "NewPostHandler"

        # Refresh our stored Jinja inkpenbam_session variable
        stored_jinja_session = self._get_jinja_variable_session()
        if stored_jinja_session is None:
            self._set_jinja_variable_session()

        # Get referrer source
        source = self.get_ref_source()

        if source is not None:
            if messages_viewed == 1:
                # Clear our previous session messages to display clean page
                print "Previously displayed errors. So clearing..."
                self.clear_main_msg()

        # Get User Messages to display if applicable
        main_user_msgs = self.get_main_msg()
        msg_type = self.get_msg_type()

        print ("NEW Post request received...")

        # Check for logged in/valid user
        auth = Authenticator(self)
        auth_check = auth.authenticate()

        # Set our base variables based on Auth result
        user = auth_check.get("user")
        user_logged_in = auth_check.get("user_logged_in")
        user_valid = auth_check.get("user_valid")

        # Case 1: User is BOTH Logged In and VALID
        if user_logged_in is True and user_valid is True:
            # Then we have a valid user logged in
            # and can proceed to allow a new post
            # Allow redirection to NEW Post page
            self.render("newpost.html", subject_validation="",
                        content_validation="",
                        main_user_msgs=main_user_msgs,
                        msg_type=msg_type)

        # Mark any Error msgs as viewed if applicable
        if self.get_main_msg is not None and self.get_main_msg != "":
            self.session["messages_viewed"] = 1
            self._set_jinja_variable_session()

        # Case 2: User is NOT logged in, or NOT valid
        if user_logged_in is False or user_valid is False:
            # Redirect to login page
            self.set_main_msg("""You need to <a href='/blog/login'>Login</a>
                              to ADD a post.""")
            self.set_msg_type("error")
            self.session["messages_viewed"] = 0
            self._set_jinja_variable_session()
            self.redirect("/blog/login")

    def post(self):
        # Check for logged in/valid user
        auth = Authenticator(self)
        auth_check = auth.authenticate()

        # Set our base variables based on Auth result
        user = auth_check.get("user")
        user_logged_in = auth_check.get("user_logged_in")
        user_valid = auth_check.get("user_valid")
        created_by = None

        # Case 1: User is NOT logged on, or NOT valid
        if user_logged_in is False and user_valid is False:
            print "Either NOT Logged In, or NOT VALID..."
            # Clear existing session data (as not logged in)
            try:
                self.clear_main_msg()
                self.clear_msg_type()
                self.set_main_msg("""Please <a href='/blog/login'> Login </a>
                                  to ADD a post.""")
                self.set_msg_type("error")
                self.session["messages_viewed"] = 0
                self._set_jinja_variable_session()
                # Redirect to LOGIN page
                self.redirect("/blog/login")
            except LookupError:
                print "Cannot add session variables on add Post error."
            finally:
                print "USER Not Logged IN....for NEW Post"

        # Case 2: User IS VALID and IS LOGGED IN
        if user_logged_in is True and user_valid is True:
            # Proceed to add the validate NEW post info, then add
            # Set our post values
            created_by = user.username
            subject = self.request.get("subject")
            content = self.request.get("content")

            # Set our validation form defaults
            subject_validation = ""
            content_validation = ""
            validation_error = False

            # Validate what Logged In/Valid user submitted
            if subject == "":
                subject_validation = ("""You must enter a SUBJECT
                                  before submitting...""")
                validation_error = True

            if content == "":
                content_validation = ("""You must enter CONTENT
                                  text before submitting...""")
                validation_error = True

            # Set default messaging values
            main_user_msgs = None
            msg_type = None

            # Check if we have a validation error. If so, set msg to client
            if validation_error is True:
                print ("""We have a validation error....
                       setting Main Msg for user...""")
                self.clear_main_msg()
                self.clear_msg_type()
                self.set_main_msg("Post values missing...")
                self.set_msg_type("error")
                main_user_msgs = self.get_main_msg()
                msg_type = self.get_msg_type()

                # Update session variables
                self.session["messages_viewed"] = 1
                self._set_jinja_variable_session()

            """
            If all is well, add the post...Otherwise render
            the page with errors
            """
            if validation_error is False:
                self.__add_new_post(subject, content, created_by)
            else:
                self.render("newpost.html", subject=subject, content=content,
                            subject_validation=subject_validation,
                            content_validation=content_validation,
                            main_user_msgs=main_user_msgs, msg_type=msg_type)


class PostHandler(Handler):
    """
    GET call is a Permalink Handler for individual posts permalink pages
    """
    def get(self, post_id):
        # print post_id
        post = Post.get_by_id(long(post_id))

        if post is not None:
            if self._get_jinja_variable_session() is not None:
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
                delete_handler = DeletePostHandler(self, post_id)
                delete_handler.delete()
            elif method == "EDIT-FORM-REQUEST":
                # This is a main post edit REQUEST,
                # not direct edit action submit.
                subject = None
                content = None
                initial_render = "true"
                edit_handler = EditPostHandler(self, post_id, subject, content,
                                               initial_render)
                edit_handler.edit_post()
            elif method == "EDIT":
                # Edit our Post ACTION, Pass Subject/Content that was posted
                subject = self.request.get("subject")
                content = self.request.get("content")
                edit_handler = EditPostHandler(self, post_id, subject, content)
                edit_handler.edit_post()
            elif method == "LIKE":
                # Like a Post Request
                like_handler = LikePostHandler(self, post_id)
                like_handler.like()
            elif method == "COMMENT":
                # Comment on a Post Request
                comment_handler = PostCommentHandler(self, post_id)
                comment_handler.comment()

    def clear_postform_errors(self, post_id):
        print "Clearing any PREVIOUSLY set post_form_error for Posts"

        posts = Post.all()
        for post in posts:
            try:
                print post.key().id()
                if post_id == post.key().id():
                    post_form_error = (self.session.get('post_%s_form_error'
                                       % post.key().id()))
                else:
                    self.session['post_%s_form_error' % post.key().id()] = ""
            except LookupError:
                print "FAILURE clearing Post Form Errors..."
            finally:
                self._set_jinja_variable_session()

        print "Exiting clear_postform_errors()"

    def set_post_likes(self, web_obj, posts, user):
        print "Setting any PREVIOUS Likes for Current User"

        for p in posts:
            try:
                post_like = user.user_likes.filter('post =', p).get()
                if post_like is not None:
                    print ("Found a post liked on post")
                    if post_like.liked == "true":
                        print "post...liked is true"
                        web_obj.session["like_%s_status" %
                                        p.key().id()] = "true"
                    else:
                        print "post...liked is false"
                        web_obj.session["like_%s_status" %
                                        p.key().id()] = "false"
                else:
                    print post_like
            except LookupError:
                print "Error setting Post Likes for Current User..."
            finally:
                web_obj._set_jinja_variable_session()

        print "Finished setting LIKES on Posts for Current User."

    def style_postform_buttons(self, web_obj, posts, user):
        print "Styling post for buttons for the Current User"

        for p in posts:
            try:
                if p.created_by == user.username:
                    print ("""User is owner of Post...
                           so updating session variables""")
                    web_obj.session["post_%s_owner" %
                                    p.key().id()] = "true"
                else:
                    print "...this is someone else's post...."
                    web_obj.session["post_%s_owner" %
                                    p.key().id()] = "false"
            except LookupError:
                print "Eror styling post form buttons by OWNER"
            finally:
                web_obj._set_jinja_variable_session()


class DeletePostHandler:
    def __init__(self, web_obj, post_id):
        self.web_obj = web_obj
        self.post_id = post_id

    def delete(self):
        print "IN: DeletePostHandler.delete()"
        self.web_obj.session["curr_handler"] = "DeletePostHandler"

        curr_post = Post.get_by_id(long(self.post_id))

        post_form_error = ""
        try:
            if self.web_obj.session is not None:
                if (self.web_obj.session.get('post_%s_form_error' %
                                             self.post_id) is not None):
                    # Clear our Post Form Errors
                    self.web_obj.clear_postform_errors(self.post_id)
            # Clear our Main MSG area
            self.web_obj.clear_main_msg()
        except LookupError:
            print "Nothing exists in POST_FORM_ERROR value in session."

        print ("DELETE Post received")

        # Check for logged in/ valid user
        auth = Authenticator(self.web_obj)
        auth_check = auth.authenticate()

        # Set our base variables based on Auth result
        user = auth_check.get("user")
        user_logged_in = auth_check.get("user_logged_in")
        user_valid = auth_check.get("user_valid")

        # Case 1: User is NOT logged in, or NOT valid
        if user_logged_in is False or user_valid is False:
            print "Either NOT Logged In, or Not VALID..."
            # Clear existing session data (as not logged in)
            try:
                # Reset message for Clicked Post
                self.web_obj.session['post_%s_form_error' % self.post_id] = (
                                                                """DELETE
                                                                requires
                                                                Login!""")

                # Set MAIN User MSG Text
                print "post subject is: %s" % curr_post.subject
                post_short_tag = "'%s...'" % curr_post.subject[0:20]
                self.web_obj.set_main_msg("""Please <a href='/blog/login'>
                                           Login</a> to DELETE post: %s"""
                                          % post_short_tag)

                self.web_obj.set_msg_type("error")

                print ("After DELETE click, session data is: %s" %
                       self.web_obj.session)

                # Set error message to NOT viewed
                self.web_obj.session["messages_viewed"] = 0

                # Update STORED Jinja global session variable
                # (for potential use in templates)
                self.web_obj._set_jinja_variable_session()

                # web_obj.redirect("/blog") Redirecting to Login instead
                self.web_obj.redirect("/blog/login")
            except LookupError:
                print "Cannot add session variable in DELETE Post"

            print "USER Not Logged in....for DELETE"

        # Case 2: User IS VALID and IS LOGGED IN
        if user_logged_in is True and user_valid is True:
            # Then we have a user valid user logged in
            # and can proceed toward deleting post

            # Used in Notice to User below on successful delete
            post_subject = curr_post.subject[:20]

            # Ensure our current post object is not NONE
            if curr_post is not None:
                # Check that DELETE clicker is POST created_by OWNER
                if curr_post.created_by == user.username:
                    print "User is OWNER of Post. *CAN* Delete"
                    # Post Deletion
                    curr_post.delete()

                    # Check to make sure post is deleted
                    post_check = Post.get_by_id(long(self.post_id))
                    print "Post Check returned: %s" % post_check

                    # Redirect if Post instance deleted successfully
                    if post_check is None:
                        # Display notice message saying that post was deleted
                        self.web_obj.clear_main_msg()
                        self.web_obj.clear_msg_type()
                        self.web_obj.set_main_msg('''Success in deleting
                                             Post: "%s"''' % post_subject)
                        self.web_obj.set_msg_type("notice")

                        # Update session variables
                        # Update session to reflect this user as post owner
                        del (
                          self.web_obj.session["post_%s_owner" % self.post_id])
                        self.web_obj.session["messages_viewed"] = 0
                        self.web_obj._set_jinja_variable_session()
                        self.web_obj.redirect("/blog/welcome")
                    else:
                        print "DELETE of POST instance failed!"
                # USER is NOT OWNER of POST. So Can't DELETE
                else:
                    print """*ERROR in DELETING post with
                              logged in AND valid user*"""
                    # Display error message saying that
                    # you need to be post Owner to DELETE
                    self.web_obj.clear_main_msg()
                    self.web_obj.clear_msg_type()
                    self.web_obj.set_main_msg("""You can ONLY delete
                                              your own posts...""")
                    self.web_obj.set_msg_type("error")

                    # Update session variables
                    self.web_obj.session["messages_viewed"] = 0
                    self.web_obj._set_jinja_variable_session()

                    self.web_obj.redirect("/blog/welcome")


class EditPostHandler:
    def __init__(self, web_obj, post_id, subject, content,
                 initial_render=None):
        self.web_obj = web_obj
        self.post_id = post_id
        self.subject = subject
        self.content = content
        self.initial_render = initial_render

    def edit_post(self):
        print "IN: EditPostHandler.edit_post()"
        self.web_obj.session["curr_handler"] = "EditPostHandler"

        curr_post = Post.get_by_id(long(self.post_id))

        # Used in Notice to User below on successful delete
        post_subject = curr_post.subject[:20]

        post_form_error = ""
        try:
            if self.web_obj.session is not None:
                if self.web_obj.session.get('post_%s_form_error'
                                            % self.post_id) is not None:
                    post_form_error = self.web_obj.session.get(
                            'post_%s_form_error' % self.post_id)

                    print "*Post_FORM_ERROR: %s" % post_form_error

                    # Clear Post Form Errors
                    self.web_obj.clear_postform_errors(self.post_id)

            # Clear our Main MSG area
            self.web_obj.clear_main_msg()
            # self.session['main_user_msgs'] = ""
        except LookupError:
            print "Nothing exists in POST_FORM_ERROR value in session."

        print ("EDIT Post received")
        print ("post_form_error val currently set to: " + post_form_error)

        # Check for logged in/valid user
        auth = Authenticator(self.web_obj)
        auth_check = auth.authenticate()

        # Set our base variables based on Auth result
        user = auth_check.get("user")
        user_logged_in = auth_check.get("user_logged_in")
        user_valid = auth_check.get("user_valid")

        # Case 1: User is NOT logged in, or NOT valid
        if user_logged_in is False or user_valid is False:
            print "Either NOT Logged In, or Not VALID...."
            # Clear existing session data (as not logged in)
            try:
                # Reset message for Clicked Post
                self.web_obj.session['post_%s_form_error' % self.post_id] = (
                                            "Must Login to EDIT!")

                # Set MAIN User MSG Text
                print "post subject is: %s" % curr_post.subject
                post_short_tag = "'%s...'" % curr_post.subject[0:20]
                self.web_obj.set_main_msg("""Please <a href='/blog/login'>
                                           Login</a> to EDIT post: %s""" %
                                          post_short_tag)
                self.web_obj.set_msg_type("error")

                print ("After EDIT click, session data is: %s" %
                       self.web_obj.session)

                # Set error message to NOT viewed
                self.web_obj.session["messages_viewed"] = 0

                # Update STORED Jinja global session variable
                # (for potential use in templates)
                self.web_obj._set_jinja_variable_session()

                # self.redirect("/blog")  #Redirecting to Login instead
                self.web_obj.redirect("/blog/login")
            except LookupError:
                print "Cannot add session variable in Edit Post"

            print "USER Not Logged in....for EDIT"

        # Case 2: User IS VALID and IS LOGGED IN
        if user_logged_in is True and user_valid is True:
            # Then we have a user valid user logged in and
            # can proceed toward EDITING post

            # Ensure that curr_post is not NONE:
            if curr_post is not None:
                # Check that EDIT clicker is POST created_by OWNER
                if curr_post.created_by == user.username:
                    print "User is OWNER of Post. *CAN* Edit"
                    # Post Edit
                    # EDIT POST HERE
                    if ((self.subject is None and self.content is None) or
                            (self.subject == "" or self.content == "")):
                        # Render our EditPost page for post editing
                        if (self.initial_render == "true"):
                            print "Initial EDIT-FORM-REQUEST received...."
                            # Set our default form values to
                            # what is in datastore
                            self.subject = curr_post.subject
                            self.content = curr_post.content

                        subject_validation = ""
                        content_validation = ""
                        validation_error = False

                        if self.subject == "":
                            subject_validation = """Post must contain a
                                                    SUBJECT before submit..."""
                            validation_error = True

                        if self.content == "":
                            content_validation = """Post must contain CONTENT
                                                    before submit..."""
                            validation_error = True

                        main_user_msgs = ""
                        msg_type = None

                        if validation_error is True:
                            print """We have a validation error...
                                     Setting Main MSG for user..."""
                            self.web_obj.clear_main_msg()
                            self.web_obj.clear_msg_type()
                            self.web_obj.set_main_msg("Edit values missing...")
                            self.web_obj.set_msg_type("error")
                            main_user_msgs = self.web_obj.get_main_msg()
                            msg_type = self.web_obj.get_msg_type()

                            # Update session variables
                            self.web_obj.session["messages_viewed"] = 1
                            self.web_obj._set_jinja_variable_session()

                        self.web_obj.render("editpost.html", post=curr_post,
                                            subject=self.subject,
                                            content=self.content,
                                            subject_validation=(
                                                subject_validation),
                                            content_validation=(
                                                content_validation),
                                            main_user_msgs=main_user_msgs,
                                            msg_type=msg_type)
                    else:
                        # Use the values from the request
                        print ("""Post subject and content received...
                               Performing Update....""")
                        curr_post.subject = self.subject
                        curr_post.content = self.content
                        curr_post.put()

                        # Check to make sure post still exists
                        post_check = Post.get_by_id(long(self.post_id))
                        print "Post Check returned: %s" % post_check

                        # Notify if can't find Post instance for some reason
                        if post_check is None:
                            print "CANNOT find Post instance!"
                        else:
                            print "SUCCESS Editing Post instance!"
                            # Display notice message saying
                            # that post was Edited
                            self.web_obj.clear_main_msg()
                            self.web_obj.clear_msg_type()
                            self.web_obj.set_main_msg('''Success in editing
                                                       Post: "%s"''' %
                                                      post_subject)
                            self.web_obj.set_msg_type("notice")

                            # Update session variables
                            self.web_obj.session["messages_viewed"] = 0
                            self.web_obj._set_jinja_variable_session()

                        self.web_obj.redirect("/blog/welcome")
                # USER is NOT OWNER of POST. So Can't EDIT
                else:
                    print ("""ERROR in EDITING post with logged in
                           AND valid user""")
                    # Display error message saying that you need
                    # to be post Owner to EDIT
                    self.web_obj.clear_main_msg()
                    self.web_obj.clear_msg_type()
                    self.web_obj.set_main_msg("""You can ONLY edit
                                               your own posts...""")
                    self.web_obj.set_msg_type("error")

                    # Update session variables
                    self.web_obj.session["messages_viewed"] = 0
                    self.web_obj._set_jinja_variable_session()

                    self.web_obj.redirect("/blog/welcome")


class LikePostHandler:
    def __init__(self, web_obj, post_id):
        self.web_obj = web_obj
        self.post_id = post_id

    def like(self):
        print "IN: LikePostHandler.like()"
        self.web_obj.session["curr_handler"] = "LikePostHandler"

        curr_post = Post.get_by_id(long(self.post_id))

        post_form_error = ""
        try:
            if self.web_obj.session is not None:
                if (self.web_obj.session.get('post_%s_form_error'
                                             % self.post_id) is not None):
                    # Clear our Post Form Errors
                    self.web_obj.clear_postform_errors(self.post_id)
            # Clear our Main MSG area
            self.web_obj.clear_main_msg()
        except LookupError:
            print "Nothing exists in POST_FORM_ERROR value in session."

        print ("LIKE Post received")

        # Check for logged in/valid user
        auth = Authenticator(self.web_obj)
        auth_check = auth.authenticate()

        # Set our base variables based on Auth result
        user = auth_check.get("user")
        user_logged_in = auth_check.get("user_logged_in")
        user_valid = auth_check.get("user_valid")

        # Like CASE 1: User is NOT Logged in, or NOT Valid
        if user_logged_in is False or user_valid is False:
            print "Either NOT Logged In, or Not VALID..."
            # Clear existing session data (as not logged in)
            try:
                # Reset message for Clicked Post
                self.web_obj.session['post_%s_form_error' % self.post_id] = (
                                                                """LIKE
                                                                requires
                                                                Login!""")

                # Set MAIN User MSG Text
                print "post subject is: %s" % curr_post.subject
                post_short_tag = "'%s...'" % curr_post.subject[0:20]
                self.web_obj.set_main_msg("""Please <a href='/blog/login'>
                                           Login</a> to LIKE post: %s""" %
                                          post_short_tag)
                self.web_obj.set_msg_type("error")

                print ("After LIKE click, session data is: %s" %
                       self.web_obj.session)

                # Set error message to NOT viewed
                self.web_obj.session["messages_viewed"] = 0

                # Update STORED Jinja global session variable
                # (for potential use in templates)
                self.web_obj._set_jinja_variable_session()

                # self.redirect("/blog") Redirecting to Login instead
                self.web_obj.redirect("/blog/login")
            except LookupError:
                print "Cannot add session variable in LIKE Post"

            print "USER Not Logged in....for LIKE"

        # Case 2: User IS VALID and IS LOGGED IN
        if user_logged_in is True and user_valid is True:
            # Then we have a user valid user logged in and
            # can proceed toward liking post

            # Used in Notice to User below on successful delete
            post_subject = curr_post.subject[:20]

            # Ensure curr_post is not NONE:
            if curr_post is not None:
                # Check that LIKE clicker is NOT the POST created_by OWNER
                if curr_post.created_by != user.username:
                    print "User is NOT OWNER of Post so *CAN* Like"
                    # Post Like Allowed
                    print ("""Checking to see if 'user' has liked
                           this post before""")

                    my_post_likes = curr_post.post_likes.filter('user =',
                                                                user)
                    if my_post_likes.get() is None:
                        print "No LIKE exists for this USER on this post...."
                        print ("""*****Marking Post as LIKED
                               by USER 1st time*****""")
                        like = Like(post=curr_post, user=user, liked="true")
                        key = like.put()

                        # Validate like for user exists now
                        like_check = Like.get(key)
                        print "New post LIKE is: %s" % like_check

                        # Set Messages and Redirect back to Welcome Home Page
                        # Display notice message saying that post was liked
                        self.web_obj.clear_main_msg()
                        self.web_obj.clear_msg_type()
                        self.web_obj.set_main_msg('LIKED Post: "%s"' %
                                                  post_subject)
                        self.web_obj.set_msg_type("notice")

                        # Update session variables
                        self.web_obj.session["messages_viewed"] = 0

                        self.web_obj.session["like_%s_status" %
                                             curr_post.key().id()] = "true"

                        self.web_obj._set_jinja_variable_session()
                        self.web_obj.redirect("/blog/welcome")
                    else:
                        print "USER has liked this post before..."

                        """
                        The following should never occur under normal
                        operation. i.e. there should never be more than
                        1 Like per User for a Post. This exists purely
                        as a failsafe cleanup..., and for convenience
                        while testing out Liking Posts during development
                        """
                        if my_post_likes.count() > 1:
                            print ("""Cleaning House. Should only be
                                   1 Post Like Per User""")
                            count = 0
                            for my_like in my_post_likes:
                                if count == 0:
                                    print "Keeping 1 Like: %s" % my_like
                                else:
                                    print "Deleting extra like"
                                    my_like.delete()

                                count += 1

                        # This output should always be 1 only per user
                        print ("""# of Times User has Liked
                               this post: %s""") % my_post_likes.count()

                        # Set our like to true/false, rather
                        # than delete completely to indicate user
                        # has previously liked an item before
                        # We toggle opposite based on what was
                        # previously stored

                        liked_obj = my_post_likes.get()
                        current_liked_val = liked_obj.liked
                        new_liked_val = None
                        liked_user_msg = None
                        if current_liked_val == "true":
                            new_liked_val = "false"
                            self.web_obj.session["like_%s_status" %
                                                 curr_post.key().id()] = (
                                                                       "false")
                            liked_user_msg = ("""You just UN-LIKED
                                              Post: %s""" % post_subject)
                        else:
                            new_liked_val = "true"
                            self.web_obj.session["like_%s_status" %
                                                 curr_post.key().id()] = "true"
                            liked_user_msg = "LIKED Post: %s" % post_subject

                        liked_obj.liked = new_liked_val
                        key = liked_obj.put()

                        # Validate like for user still exists
                        like_check = Like.get(key)
                        print ("""Post LIKE check for USER
                               returned: %s""" % like_check.liked)

                        if like_check is not None:
                            # print ("""Like Check for Like
                            #         returned: %s""" % like_check.liked)

                            # Set Messages and Redirect back
                            # to Welcome Home Page.
                            # Display notice message saying
                            # Previously Liked Post already.
                            self.web_obj.clear_main_msg()
                            self.web_obj.clear_msg_type()
                            self.web_obj.set_main_msg(liked_user_msg)
                            self.web_obj.set_msg_type("notice")

                            # Update session variables
                            self.web_obj.session["messages_viewed"] = 0
                            self.web_obj._set_jinja_variable_session()
                            self.web_obj.redirect("/blog/welcome")
                # USER IS the OWNER of POST. So Can't LIKE their OWN post
                else:
                    print """*ERROR in LIKING post with logged
                              in AND valid user*"""
                    # Display error message saying that
                    # you *must not be* the post Owner to LIKE
                    self.web_obj.clear_main_msg()
                    self.web_obj.clear_msg_type()
                    self.web_obj.set_main_msg("""You can ONLY like other
                                              people's posts...""")
                    self.web_obj.set_msg_type("error")

                    # Update session variables
                    self.web_obj.session["messages_viewed"] = 0
                    self.web_obj._set_jinja_variable_session()

                    self.web_obj.redirect("/blog/welcome")
            else:
                print "LIKING of POST instance failed as curr_post is NONE!"
                self.web_obj.clear_main_msg()
                self.web_obj.clear_msg_type()
                self.web_obj.redirect("/blog/welcome")


class PostCommentHandler:
    def __init__(self, web_obj, post_id):
        self.web_obj = web_obj
        self.post_id = post_id

    def comment(self):
        print "IN: PostCommentHandler.comment()"

        last_handler = None
        messages_viewed = 0
        try:
            last_handler = self.web_obj.session.get("curr_handler")
            messages_viewed = self.web_obj.session.get("messages_viewed")
        except LookupError:
            print "No Last Handler or Errors Viewed values exist"
        finally:
            self.web_obj.session["curr_handler"] = "PostHandler"

        curr_post = Post.get_by_id(long(self.post_id))

        post_form_error = ""
        try:
            if self.web_obj.session is not None:
                if self.web_obj.session.get('post_%s_form_error' %
                                            self.post_id) is not None:
                    # Clear out Post Form Erorrs
                    self.web_obj.clear_postform_errors(self.post_id)
            # Clear our Main MSG area
            self.web_obj.clear_main_msg()
        except LookupError:
            print "Nothing exists in POST_FORM_ERROR value in session."

        print ("COMMENT Post received")

        # Check for logged in/valid user
        auth = Authenticator(self.web_obj)
        auth_check = auth.authenticate()

        # Set our base variables based on Auth result
        user = auth_check.get("user")
        user_logged_in = auth_check.get("user_logged_in")
        user_valid = auth_check.get("user_valid")

        # Case 1: User is NOT logged in, or NOT valid
        if user_logged_in is False or user_valid is False:
            print "Either NOT Logged In, or Not VALID..."
            # Clear existing session data (as not logged in)
            try:
                # Reset message for Clicked Post
                self.web_obj.session["post_%s_form_error" % self.post_id] = (
                                                                """COMMENT
                                                                requires
                                                                Login!""")

                # Set MAIN User MSG Text
                print "post subject is: %s" % curr_post.subject
                post_short_tag = "'%s...'" % curr_post.subject[0:20]
                self.web_obj.set_main_msg("""Please <a href='/blog/login'>
                                           Login</a> to COMMENT on post: %s"""
                                          % post_short_tag)
                self.web_obj.set_msg_type("error")

                print ("After COMMENT click, session data is: %s" %
                       self.web_obj.session)

                # Set error message to NOT viewed
                self.web_obj.session["messages_viewed"] = 0

                # Update STORED Jinja global session
                # variable (for use in templates)
                self.web_obj._set_jinja_variable_session()

                # Redirect to LOGIN page
                self.web_obj.redirect("/blog/login")
            except LookupError:
                print "Cannot add session variable in COMMENT Post"

            print "USER Not Logged in...for COMMENT"

        """
        PASS COMMENT POST control for VALID and LOGGED IN User
        to our END-point handler
        """
        # Case 2: User IS VALID and IS LOGGED IN
        if user_logged_in is True and user_valid is True:
            # Then we can proceed to COMMENT on post

            # Get User Messages to display if applicable
            # main_user_msgs = self.get_main_msg()
            # msg_type = self.get_msg_type()

            # Used in Notice to User below on successful comment
            # post_subject = curr_post.subject[:20]

            if curr_post is not None:
                print "We are about to add a comment...."
                self.web_obj.redirect("/blog/%s/comment" % self.post_id)
                # self.render("newcomment.html", comment_validation="",
                # main_user_msgs=main_user_msgs, msg_type=msg_type,
                # post=curr_post, post_subject=post_subject)
            else:
                self.web_obj.redirect("/blog/welcome")


"""
COMMENT/REPLY
*Action* specific Handlers:
--NewCommentHandler:
    *Endpoint handler for new
    *initial comments to a post
--CommentActionHandler:
    *get/post main point of Entry
    *for remaining operations of:
        --Delete, Edit, Reply,
        --etc...
--DeleteCommentHandler:
    *controls DELETE activity on a Comment
--EditCommentHandler:
    *controls EDIT activity on a Comment
--CommentReplyHandler:
    *controls REPLY activity on a COMMENT
#####################################
"""


class NewCommentHandler:
    """
    As per our DB we will need: a) post instance,
    b) user instance, c) parent_ Comment instance,
    d) comment text body, and e) created_by
    (user instance user.username) to
    create a new comment for the post
    """
    def __init__(self, web_obj, post_id):
        self.web_obj = web_obj
        self.post_id = post_id

    def __add_new_comment(self, post, user, comment, parent=None):
        """
        No need for user login check/validation here
        as this function is only called through other endpoints.
        i.e. it isn't accessible through own endpoint
        Existing endpoints already check authencation before this point.
        In any event, if user=None, it would mean we couldn't
        add a comment.
        """
        # User at this point would be VALID and IS LOGGED IN
        # We can proceed to add our NEW comment
        if user:
            c = Comment(post=post, user=user, comment_parent=parent,
                        comment=comment, created_by=user.username)
            key = c.put()

            # Do quick lookup of comment just put()
            new_comment = Comment.get(key)
            print "New comment is: %s" % new_comment

            # Update session to reflect this user as 'post-comment owner
            self.web_obj.session["post_%s_comment_%s_owner" %
                                 (post.key().id(), c.key().id())] = "true"
            self.web_obj._set_jinja_variable_session()

            # Redirect to blog post permalink page which displays comments
            self.web_obj.redirect("/blog/%s" % post.key().id())

    def set_needlogin_msg(self):
        # Set Base Need Login to COMMENT error message
        self.web_obj.clear_main_msg()
        self.web_obj.clear_msg_type()
        self.web_obj.set_main_msg("""You need to <a href='/blog/login'>
                                   Login</a> to COMMENT on a post.""")
        self.web_obj.set_msg_type("error")
        self.web_obj.session["messages_viewed"] = 0
        self.web_obj._set_jinja_variable_session()

    def post_comment(self):
        # Check for logged in/valid user
        auth = Authenticator(self.web_obj)
        auth_check = auth.authenticate()

        # Set our base variables based on Auth result
        user = auth_check.get("user")
        user_logged_in = auth_check.get("user_logged_in")
        user_valid = auth_check.get("user_valid")

        # Case 1: User is NOT LOGGED In, or NOT Valid
        if user_logged_in is False or user_valid is False:
            # Set our Error msg and Redirect to Login
            self.set_needlogin_msg()
            self.redirect("/blog/login")

        # Case 2: We have a LOGGED IN and VALID user
        if user_logged_in is True and user_valid is True:
            # Proceed with Post Comment request
            post_id = self.post_id
            post = Post.get_by_id(long(post_id))
            comment = self.web_obj.request.get("comment")

            comment_validation = ""
            validation_error = False

            # Perform comment validation
            if comment == "":
                # Create a validation error and msg
                comment_validation = ("""Comment text must be entered
                                      before submit...""")
                validation_error = True

            main_user_msgs = None
            msg_type = None
            if validation_error is True:
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
            If all OK add our Comment, else
            re-render page with error msg
            """
            if validation_error is False:
                self.__add_new_comment(post, user, comment)
            else:
                web_obj.render("newcomment.html", post=post,
                               post_subject=post.subject[:20],
                               comment=comment,
                               comment_validation=comment_validation,
                               main_user_msgs=main_user_msgs,
                               msg_type=msg_type)


class CommentActionHandler(Handler):
    def get(self, post_id, comment_id=None):
        print "IN: CommentActionHandler()"

        # Determine if we are viewing an existing comment
        # or adding a new comment
        if post_id and comment_id is not None:
            print "Post ID: %s, Comment ID: %s" % (post_id, comment_id)
        elif comment_id is None:
            print "Receiving a NEW Comment request for post: %s" % post_id

        curr_post = Post.get_by_id(long(post_id))
        # Used in Templates for new Comment below
        post_subject = curr_post.subject[:20]

        last_handler = None
        messages_viewed = 0
        try:
            last_handler = self.session.get("curr_handler")
            messages_viewed = self.session.get("messages_viewed")
        except LookupError:
            print "No Last Handler or Errors Viewed values exist"
        finally:
            self.session["curr_handler"] = "PostCommentHandler"

        # Refresh our stored Jinja inkpenbam session variable
        stored_jinja_session = self._get_jinja_variable_session()
        if stored_jinja_session is None:
            self._set_jinja_variable_session()

        # Get referrer source
        source = self.get_ref_source()
        if source is not None:
            if messages_viewed == 1:
                # Clear any previous session messages to display clean page
                print "Previously displayed errors. So clearing..."
                self.clear_main_msg()

        # Get User Messages to display if applicable
        main_user_msgs = self.get_main_msg()
        msg_type = self.get_msg_type()

        # Check for logged in/valid user
        auth = Authenticator(self)
        auth_check = auth.authenticate()

        # Set our base variables based on Auth result
        user = auth_check.get("user")
        user_logged_in = auth_check.get("user_logged_in")
        user_valid = auth_check.get("user_valid")

        # Case 1: User is NOT logged in, or NOT Valid
        if user_logged_in is False or user_valid is False:
            print "Either NOT Logged In, or Not Valid..."
            self.set_main_msg("""You need to <a href='/blog/login'>Login</a>
                              to COMMENT on a post.""")
            self.set_msg_type("error")
            self.session["messages_viewed"] = 0
            self._set_jinja_variable_session()
            self.redirect("/blog/login")

            print "Cookie invalid @ PostCommentHandler!"

        # Case2: User is LOGGED in and VALID
        if user_logged_in is True and user_valid is True:
            # We can proceed to render our newcomment form
            # Allow redirection to NEW Comment oage
            self.render("newcomment.html", comment_validation="",
                        main_user_msgs=main_user_msgs,
                        msg_type=msg_type, post=curr_post,
                        post_subject=post_subject)

        # Mark any Error msgs as viewed if applicable
        if self.get_main_msg() is not None and self.get_main_msg() != "":
            self.session["messages_viewed"] = 1
            self._set_jinja_variable_session()

    def post(self, post_id, comment_id=None):
        if comment_id is None:
            # We have a *initial* top level new COMMENT action
            print "Received an *initial* top level new comment request..."
            # Send to handler method
            comment_action = NewCommentHandler(self, post_id)
            comment_action.post_comment()
        else:
            # We have an existing COMMENT action
            url_post_id = post_id
            url_comment_id = comment_id
            method = self.request.get("_method").upper()
            comment_id = self.request.get("comment_id")

            if url_comment_id == comment_id:
                print "Received a %s request for comment...." % method
                if method == "REPLY-FORM-REQUEST":
                    # This is a main reply REQUEST,
                    # not a direct REPLY action body submit
                    reply_body = None
                    initial_render = "true"
                    reply_handler = CommentReplyHandler(self, comment_id,
                                                        post_id, reply_body,
                                                        initial_render)
                    reply_handler.get_reply_frm()
                elif method == "REPLY":
                    # Add a comment reply ACTION caller
                    # Pass REPLY text as posted
                    print "...in case...REPLY"
                    reply_body = self.request.get("reply")
                    reply_handler = CommentReplyHandler(self, comment_id,
                                                        post_id, reply_body)
                    reply_handler.get_reply_frm()
                elif method == "EDIT-FORM-REQUEST":
                    # This is a main comment edit REQUEST,
                    # not a direct edit action submit.
                    comment_body = None
                    initial_render = "true"
                    edit_comment_handler = EditCommentHandler(self, comment_id,
                                                              comment_body,
                                                              post_id,
                                                              initial_render)
                    edit_comment_handler.edit_comment()
                elif method == "EDIT":
                    # Edit comment ACTION caller
                    # Pass COMMENT text as posted
                    print "...in case...EDIT"
                    comment_body = self.request.get("comment")
                    edit_comment_handler = EditCommentHandler(self, comment_id,
                                                              comment_body,
                                                              post_id)
                    edit_comment_handler.edit_comment()
                elif method == "DELETE":
                    # Delete our Comment right
                    print "...in case...DELETE"
                    delete_comment_handler = DeleteCommentHandler(self,
                                                                  comment_id,
                                                                  post_id)
                    delete_comment_handler.delete_comment()

    def clear_commentform_errors(self, comment_id, post_id):
        print "Clearing any PREVIOUSLY set comment_form_error for Comments"

        comments = Comment.all()
        for comment in comments:
            try:
                if comment_id == comment.key().id():
                    comment_form_error = (
                            self.session.get("post_%s_comment_%s_form_error"
                                             % (post_id, comment_id)))
                else:
                    self.session["post_%s_comment_%s_form_error" %
                                 (post_id, comment_id)] = ""
            except LookupError:
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
                    print ("""User is owner of Comment...
                           so updating session variables""")
                    web_obj.session["post_%s_comment_%s_owner" %
                                    (post.key().id(), c.key().id())] = "true"
                else:
                    print "...this is someone else's comment..."
                    web_obj.session["post_%s_comment_%s_owner" %
                                    (post.key().id(), c.key().id())] = "false"
            except LookupError:
                print "Error styling comment button on posts by OWNER"
            finally:
                web_obj._set_jinja_variable_session()

        print "Existing style_commentform_buttons()"


class DeleteCommentHandler:
    def __init__(self, web_obj, comment_id, post_id):
        self.web_obj = web_obj
        self.comment_id = comment_id
        self.post_id = post_id

    def delete_comment(self):
        print "IN: DeleteCommentHandler.delete_comment()"
        self.web_obj.session["curr_handler"] = "DeleteCommentHandler"

        curr_comment = Comment.get_by_id(long(self.comment_id))
        parent_post = Post.get_by_id(long(self.post_id))

        # Used for user output later
        post_subject = parent_post.subject[:20]

        comment_form_error = ""
        try:
            post_comm_frm_tag = ("post_%s_comment_%s_form_error" %
                                 (self.post_id, self.comment_id))
            if self.web_obj.session.get(post_comm_frm_tag) is not None:
                # Clear our Comment Form Errors
                self.web_obj.clear_commentform_errors(self.comment_id,
                                                      self.post_id)
            # Clear our Main MSG area
            self.web_obj.clear_main_msg()
        except LookupError:
            print "Nothing exists in COMMENT_FORM_ERROR value in session."

        print ("DELETE Comment received...")

        # Check for a logged in / valid user
        auth = Authenticator(self.web_obj)
        auth_check = auth.authenticate()

        # Set base variables based on authentication check
        user = auth_check.get("user")
        user_logged_in = auth_check.get("user_logged_in")
        user_valid = auth_check.get("user_valid")

        # Case 1: User is NOT Logged, or User is NOT Valid
        if user_logged_in is False or user_valid is False:
            print "Either NOT Logged In, or NOT Valid..."
            # set error message for user
            try:
                self.web_obj.session["post_%s_comment_%s_form_error" %
                                     (self.post_id, self.comment_id)] = (
                                                                   """DELETE
                                                                   requires
                                                                   Login!""")
                self.web_obj.set_main_msg("""Please <a href='/blog/login'>
                                           Login</a> to DELETE comment
                                           for post: '%s...'"""
                                          % post_subject)
                self.web_obj.set_msg_type("error")
                self.web_obj.session["messages_viewed"] = 0
                self.web_obj._set_jinja_variable_session()
                self.web_obj.redirect("/blog/login")
            except LookupError:
                print "Cannot add session variables for DELETE comment action"

            print "USER Not Logged In....for DELETE comment"

        # Case 2: User IS Logged in and IS Valid
        if user_logged_in is True and user_valid is True:
            # Then we can delete this comment, if they are comment owner
            # Ensure curr_comment is not NONE
            if curr_comment is not None:
                if curr_comment.created_by == user.username:
                    print "User is OWNER of Comment. *CAN* Delete"
                    # Comment Deletion (includes children)
                    try:
                        def del_comment_session_val(c):
                            # Delete master parent session info, if exits
                            try:
                                del_sess_tag = ("post_%s_comment_%s_owner" %
                                                (self.post_id, c.key().id()))
                                del self.web_obj.session[del_sess_tag]
                            except LookupError:
                                print "Comment session info delete fail!"
                            finally:
                                print "Existing del_comment_session_val..."

                        def del_curr_comment(c):
                            if c.replies.count() == 0:
                                print "in case no children"
                                # Delete descendant session info
                                del_comment_session_val(c)
                                # Recursive descendant delete
                                c.delete()
                            else:
                                for c_child in c.replies:
                                    print "in case child"
                                    del_comment_session_val(c_child)
                                    # Call delete
                                    del_curr_comment(c_child)

                                # Delete root child
                                del_comment_session_val(c_child)
                                c_child.delete()
                                # Delete the master parent, 'curr_comment'
                                del_comment_session_val(c)
                                c.delete()
                        # Call recursive delete on current comment entity
                        del_curr_comment(curr_comment)
                    except LookupError:
                        print (""""Error deleting comments and
                               associated replies....""")
                    finally:
                        print ("""Done handling comment delete...
                               submitting output of result.""")

                    # Check to make sure comment is delete
                    comment_check = Comment.get_by_id(long(self.comment_id))
                    print "Comment Check returned: %s" % comment_check

                    # Redirect if Comment instance deleted successfully
                    if comment_check is None:
                        # Clear any messages
                        self.web_obj.clear_main_msg()
                        self.web_obj.clear_msg_type()
                        # Set success msg
                        self.web_obj.set_main_msg(('''Success in deleting
                                                    COMMENT for Post: "%s"''')
                                                  % post_subject)
                        self.web_obj.set_msg_type("notice")

                        # Update session variable
                        self.web_obj.session["messages_viewed"] = 0
                        self.web_obj._set_jinja_variable_session()
                        self.web_obj.redirect("/blog/welcome")
                    else:
                        print "DELETE of COMMENT instance failed!"
                # Case 3: USER is NOT Owner of COMMENT here. So Can't DELETE
                else:
                    print ("""ERROR in DELETING comment instance with
                           logged in and valid user...""")
                    # Display error message indicating they need to
                    # be comment owner to delete
                    self.web_obj.clear_main_msg()
                    self.web_obj.clear_msg_type()
                    self.web_obj.set_main_msg("""You can ONLY delete your
                                      own comments...""")
                    self.web_obj.set_msg_type("error")

                    # Update session variables
                    self.web_obj.session["messages_viewed"] = 0
                    self.web_obj._set_jinja_variable_session()

                    self.web_obj.redirect("/blog/welcome")


class EditCommentHandler:
    def __init__(self, web_obj, comment_id, comment_body,
                 post_id, initial_render=None):

        self.web_obj = web_obj
        self.comment_id = comment_id
        self.comment_body = comment_body
        self.post_id = post_id
        self.initial_render = initial_render

    def finalize_edit(self, post_subject, curr_comment, comment_body, user):
        """
        No need check for user login check/validation here
        as this function is only called through class functions.
        i.e. it isn't accessible through its own endpoint
        Existing endpoints already check authencation before this point.
        In any event, if user=None, it would mean we couldn't
        add a reply.
        """
        # User at this point would be VALID and IS LOGGED IN
        # We can proceed to add our NEW reply
        if user:
            # Use the values from the passed request
            print ("""Post comment body received...
                   Performing Update...""")
            curr_comment.comment = comment_body
            curr_comment.put()

            # Check to make sure comment still exists
            comment_check = (
                        Comment.get_by_id(long(self.comment_id)))
            print "Comment Check returned: %s" % comment_check

            # Notify if we can't find Comment
            # instance for some reason
            if comment_check is None:
                print "CANNOT find Comment instance!"
            else:
                print "SUCCESS Editing Comment instance!"
                # display notices indicating success
                self.web_obj.clear_main_msg()
                self.web_obj.clear_msg_type()
                self.web_obj.set_main_msg('''Success in
                                          editing COMMENT
                                          for Post: "%s"''' %
                                          post_subject)
                self.web_obj.set_msg_type("notice")

                # Update session variables
                self.web_obj.session["messages_viewed"] = 0
                self.web_obj._set_jinja_variable_session()

            self.web_obj.redirect("/blog/welcome")

    def edit_comment(self):
        print "IN: EditCommentHandler.edit_comment()"
        self.web_obj.session["curr_handler"] = "EditCommentHandler"

        curr_comment = Comment.get_by_id(long(self.comment_id))
        parent_post = Post.get_by_id(long(self.post_id))

        # Used for user output later
        post_subject = parent_post.subject[:20]

        comment_form_error = ""
        try:
            post_comm_tag = ("post_%s_comment_%s_form_error" %
                             (self.post_id, self.comment_id))
            if self.web_obj.session.get(post_comm_tag) is not None:
                # Clear our Comment Form Errors
                self.web_obj.clear_commentform_errors(self.comment_id,
                                                      self.post_id)
            # Clear our Main MSG area
            self.web_obj.clear_main_msg()
        except LookupError:
            print "Nothing exists in COMMENT_FORM_ERROR value in session."

        print ("EDIT Comment received...")

        # Check for logged in/valid user
        auth = Authenticator(self.web_obj)
        auth_check = auth.authenticate()

        # Set our base variables based on Auth result
        user = auth_check.get("user")
        user_logged_in = auth_check.get("user_logged_in")
        user_valid = auth_check.get("user_valid")

        # Case 1: User is NOT logged in, or NOT valid
        if user_logged_in is False and user_valid is False:
            print "Either NOT Logged In, or NOT Valid..."
            # set error message for user
            try:
                self.web_obj.session["post_%s_comment_%s_form_error" %
                                     (self.post_id, self.comment_id)] = (
                                     """MUST Login to EDIT a COMMENT!""")
                self.web_obj.set_main_msg("""Please <a href='/blog/login'>
                                           Login</a> to EDIT COMMENT for post:
                                           '%s...'""" % post_subject)
                self.web_obj.set_msg_type("error")
                self.web_obj.session["messages_viewed"] = 0
                self.web_obj._set_jinja_variable_session()
                self.web_obj.redirect("/blog/login")
            except LookupError:
                print "Cannot add session variables for EDIT comment action"

            print "USER Not Logged In....for EDIT comment"

        # Case 2: User IS LOGGED IN and VALID
        if user_logged_in is True and user_valid is True:
            # Comment Edit, ensure comment is not NONE
            if curr_comment is not None:
                # Then we can edit this comment, if they are comment owner
                # OWNER CHECK
                if curr_comment.created_by == user.username:
                    print "User is OWNER of Comment. *CAN* Edit"
                    # EDIT COMMENT HERE
                    if self.comment_body is None or self.comment_body == "":
                        # Render our EditComment Page for comment editing
                        if (self.initial_render == "true"):
                            # Set our default form values to
                            # what is in datastore
                            self.comment_body = curr_comment.comment

                        comment_validation = ""
                        validation_error = False

                        if self.comment_body == "":
                            comment_validation = ("""Comment must
                                                  contain TEXT body
                                                  before submit...""")
                            validation_error = True

                        main_user_msgs = ""
                        msg_type = None

                        if validation_error is True:
                            print ("""We have a validation error....
                                   So setting main message...""")
                            self.web_obj.clear_main_msg()
                            self.web_obj.clear_msg_type()
                            self.web_obj.set_main_msg("""Edit COMMENT
                                                       values missing...""")
                            self.web_obj.set_msg_type("error")
                            main_user_msgs = self.web_obj.get_main_msg()
                            msg_type = self.web_obj.get_msg_type()

                            # Update session variable
                            self.web_obj.session["messages_viewed"] = 1
                            self.web_obj._set_jinja_variable_session()

                        # Render our EDIT comment form
                        self.web_obj.render("editcomment.html",
                                            post=parent_post,
                                            comment=curr_comment,
                                            comment_body=self.comment_body,
                                            comment_validation=(
                                                comment_validation),
                                            main_user_msgs=main_user_msgs,
                                            msg_type=msg_type)
                    else:
                        # Finalize our EDIT and submit to DataStore
                        self.finalize_edit(post_subject, curr_comment,
                                           self.comment_body, user)

                # USER is NOT OWNER of COMMENT. So can't EDIT
                else:
                    print ("""ERROR in EDITING comment instance with
                           logged in and valid user...""")
                    # Display error message indicating they need
                    # to be comment owner to delete
                    self.web_obj.clear_main_msg()
                    self.web_obj.clear_msg_type()
                    self.web_obj.set_main_msg("""You can ONLY edit your
                                               own comments...""")
                    self.web_obj.set_msg_type("error")

                    # Update session variables
                    self.web_obj.session["messages_viewed"] = 0
                    self.web_obj._set_jinja_variable_session()

                    self.web_obj.redirect("/blog/welcome")


class CommentReplyHandler:
    def __init__(self, web_obj, comment_id, post_id, reply_body,
                 initial_render=None):
        self.web_obj = web_obj
        self.comment_id = comment_id
        self.post_id = post_id
        self.reply_body = reply_body
        self.initial_render = initial_render

    def __add_reply(self, parent_post, user, parent_comment, reply_body,
                    created_by):
        """
        No need check for user login check/validation here
        as this function is only called through class functions.
        i.e. it isn't accessible through its own endpoint
        Existing endpoints already check authencation before this point.
        In any event, if user=None, it would mean we couldn't
        add a reply.
        """
        # User at this point would be VALID and IS LOGGED IN
        # We can proceed to add our NEW reply
        if user:
            c = Comment(post=parent_post, user=user,
                        comment_parent=parent_comment,
                        comment=reply_body,
                        created_by=created_by)
            key = c.put()

            # Do a quick verify of add
            new_reply = Comment.get(key)
            print "New Reply is: %s" % new_reply

            # Update session to reflect user as reply
            # (i.e. a comment object) OWNER
            self.web_obj.session["post_%s_comment_%s_owner" %
                                 (parent_post.key().id(),
                                  c.key().id())] = "true"
            self.web_obj._set_jinja_variable_session()

            # Redirect to blog post permalink page which displays
            # all comments and replies
            self.web_obj.redirect("/blog/%s" % parent_post.key().id())

    def get_reply_frm(self):
        print "IN: CommentReplyHandler.get_reply_frm()"

        # OUR PARENT objects
        parent_comment = Comment.get_by_id(long(self.comment_id))
        parent_post = Post.get_by_id(long(self.post_id))

        last_handler = None
        messages_viewed = 0
        try:
            last_handler = self.web_obj.session.get("curr_handler")
            messages_viewed = self.web_obj.session.get("messages_viewed")
        except LookupError:
            print "No Last Handler or Errors Viewed values exist..."
        finally:
            self.web_obj.session["curr_handler"] = "CommentReplyHandler"

        # Refresh our stored jinja inkpenbam session variable
        stored_jinja_session = self.web_obj._get_jinja_variable_session()
        if stored_jinja_session is None:
            self.web_obj._set_jinja_variable_session()

        # Get referrer source
        source = self.web_obj.get_ref_source()
        if source is not None:
            if messages_viewed == 1:
                # Clear any previous session messages to display a clean page
                print "Previously displayed errors. So clearing..."
                self.web_obj.clear_main_msg()

        # Get User MSGS to display
        main_user_msgs = self.web_obj.get_main_msg()
        msg_type = self.web_obj.get_msg_type()

        # Used for user output later
        post_subject = parent_post.subject[:20]

        # Check for logged in/valid user
        auth = Authenticator(self.web_obj)
        auth_check = auth.authenticate()

        # Set our base variables based on Auth result
        user = auth_check.get("user")
        user_logged_in = auth_check.get("user_logged_in")
        user_valid = auth_check.get("user_valid")

        # Case 1: User is NOT LOGGED In, or NOT Valid
        if user_logged_in is False or user_valid is False:
            self.web_obj.set_main_msg("""You need to <a href='/blog/login'>
                                       Login</a> to REPLY to a
                                       post comment.""")
            self.web_obj.set_msg_type("error")
            self.web_obj.session["messages_viewed"] = 0
            self.web_obj._set_jinja_variable_session()
            self.web_obj.redirect("/blog/login")

        # Case 2: User IS LOGGED IN and VALID
        if user_logged_in is True and user_valid is True:
            # Set some default values
            reply_validation = ""
            validation_error = False
            main_user_msgs = ""
            msg_type = None
            created_by = user.username

            if self.reply_body is None and self.initial_render == "true":
                # We can just skip out initial form validation
                print "Initial REPLY-FORM-REQUEST received..."
                self.reply_body = ""
            else:
                # Then our user is submitting an actual reply,
                # from the form
                # PEFORM some validation
                if self.reply_body == "":
                    reply_validation = ("""Reply must contain REPLY
                                        text before submit...""")
                    validation_error = True

                if validation_error is True:
                    print ("""We have a validation error....
                           Setting msg for our user...""")
                    self.web_obj.clear_main_msg()
                    self.web_obj.clear_msg_type()
                    self.web_obj.set_main_msg("Reply values are missing...")
                    self.web_obj.set_msg_type("error")
                    main_user_msgs = self.web_obj.get_main_msg()
                    msg_type = self.web_obj.get_msg_type()

                    # Update session variables
                    self.web_obj.session["messages_viewed"] = 1
                    self.web_obj._set_jinja_variable_session()

            if self.reply_body == "" or validation_error is True:
                # Render our Reply Form in either case
                self.web_obj.render("newcomment-reply.html",
                                    reply_validation=reply_validation,
                                    main_user_msgs=main_user_msgs,
                                    msg_type=msg_type, post=parent_post,
                                    comment=parent_comment,
                                    post_subject=post_subject,
                                    reply=self.reply_body)
            elif self.reply_body != "" and validation_error is False:
                # Go ahead and create the reply....
                print "ADDING THE REPLY to datastore"
                self.__add_reply(parent_post, user, parent_comment,
                                 self.reply_body, created_by)

        # TODO: maybe take this commented section out if
        # we don't experience any issues without it
        # Mark any Error msgs as viewed if applicable
        # if (self.web_obj.get_main_msg() is not None
        #        and self.web_obj.get_main_msg() != ""):
        #    self.web_obj.session["messages_viewed"] = 0
        #    self.web_obj._set_jinja_variable_session()


"""
MAIN Blog, Welcome routing handlers
--Blog:
    *Endpoint handler for entry
    *into our blog app
--Welcome:
    *get/post main point of Entry
    *for Logged in / Valid User
        --Welcome PAGE,
--BlogRouter:
    *Catch-All router for
    *unknown endpoints
####################################
"""


class Blog(Handler):
    """
    Main BLOG Front Page Handler
    """
    def get(self):
        print "IN: Blog.Handler()"

        last_handler = None
        messages_viewed = 0
        try:
            last_handler = self.session.get("curr_handler")
            messages_viewed = self.session.get("messages_viewed")
        except LookupError:
            print "No Last Handler or Errors Viewed values exist"
        finally:
            self.session["curr_handler"] = "Blog"

        # Convenience stored Jinja session global
        # for potential use in templates
        stored_jinja_session = self._get_jinja_variable_session()
        if stored_jinja_session is None:
            stored_jinja_session = self._set_jinja_variable_session()

        # Check Referrer to display appropriate Errors and Messages
        source = self.get_ref_source()

        if source is not None:
            if messages_viewed == 1:
                # Clear our previous session messages to display clean page
                print "Previously display errors. So clearing...."
                self.clear_main_msg()

        # my_session = self.session
        main_user_msgs = self.get_main_msg()
        msg_type = self.get_msg_type()

        print ("""My Jinja stored session details after get/set
               _session are: %s""") % stored_jinja_session
        print "Comparing... LIVE session: %s" % self.session

        posts_exist = False
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
        # Output post.ids for debugging
        # for post in posts:
        #    print post.key().id()

        if posts.get() is not None:
            print "We have Posts"
            posts_exist = True

            if source is not None:
                if messages_viewed == 1:
                    # Clear out previous Individual Post Error messages
                    print "Previous post errors exist... Cleaning up..."

                    for p in posts:
                        try:
                            self.session['post_%s_form_error' %
                                         p.key().id()] = ""
                            # Update session to reflect logged out,
                            # and therefore not post owner
                            self.session["post_%s_owner" % p.key().id()] = ""
                            try:
                                print (("""Post has %s comments...
                                       Clearing errors...""") %
                                       p.post_comments.count())
                                for c in p.post_comments:
                                    # Do the same for comments
                                    self.session[(
                                            "post_%s_comment_%s_form_error" %
                                            (p.key().id(), c.key().id()))] = ""
                                    self.session[(
                                            "post_%s_comment_%s_owner" %
                                            (p.key().id(), c.key().id()))] = ""
                            except LookupError:
                                print ("""Cannot blank individual comment
                                       post session error...""")
                        except LookupError:
                            print (""""Cannot blank individual
                                   post session error...""")
                        finally:
                            self._set_jinja_variable_session()
                            stored_jinja_session = (
                                self._get_jinja_variable_session())

            # Fail-safe set of "inkpenbam_session" variable
            # TODO: Rather than have this here as a backup, ensure that
            # self._set_jinja_variable_session() and
            # self.get_jinja_variable_session()
            # ALWAYS work as expected. Until then...
            # this is the 'failsafe' setter for Blog home
            jinja_env = Handler()._get_jinja_env()
            jinja_env.globals['inkpenbam_session'] = stored_jinja_session

            # Render our page
            self.render("blog.html", posts=posts,
                        curr_session=stored_jinja_session,
                        main_user_msgs=main_user_msgs,
                        msg_type=msg_type)

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

        # If NO user posts yet exist, And NO User logged in
        # ...just redirect to SIGNUP page
        if ((user_logged_in is False or user_valid is False)
                and posts_exist is False):
            self.redirect("/blog/signup")

        # Mark any Error msgs as viewed if applicable
        if self.get_main_msg is not None and self.get_main_msg != "":
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
        login_msg_displayed_once = None
        # ^ So first time welcome loaded this session
        try:
            last_handler = self.session.get("curr_handler")
            messages_viewed = self.session.get("messages_viewed")
            login_msg_displayed_once = (
                self.session.get("login_msg_displayed_once"))
        except LookupError:
            print "No Last Handler or Errors Viewed values exist"
        finally:
            self.session["curr_handler"] = "Welcome"

        # Refresh our stores Jinja inkpenbam session variabl
        stored_jinja_session = self._get_jinja_variable_session()
        if stored_jinja_session is None:
            self._set_jinja_variable_session()

        # Get referrer source
        source = self.get_ref_source()

        if source is not None:
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
                user_logged_posts = db.GqlQuery("""SELECT * FROM Post WHERE
                                                created_by = :created_by
                                                ORDER BY created DESC""",
                                                created_by=username)

                if (user_logged_posts.get() is None
                        and login_msg_displayed_once is None):

                    print "No User POSTS exist...."
                    self.set_main_msg("""Hmm...you have 0 posts.
                                      Please
                                      <a href='/blog/newpost'>add some</a>.
                                      :)""")
                    main_user_msgs = self.get_main_msg()
                    msg_type = self.set_msg_type("notice")
                    self.session["messages_viewed"] = 0
                    self.session["login_msg_displayed_once"] = 1
                else:
                    self.clear_main_msg()
                    self.clear_msg_type()

                # Ensure jinja session variables are in-sync
                self._set_jinja_variable_session()

                all_posts = db.GqlQuery("""SELECT * FROM Post ORDER BY
                                        created DESC""")
                if all_posts.get() is not None:
                    # Get ALL the POSTS and set All Post *initial like*
                    # values if this is the first time viewing
                    # welcome page after login.
                    # if login_msg_displayed_once == None:
                    # Set any Post LIKEs for Current Logged in
                    # and Valid User.
                    PostHandler().set_post_likes(self, all_posts, user)
                    # Style Post Form buttons for current user
                    PostHandler().style_postform_buttons(self, all_posts, user)

                for post in all_posts:
                    if post.post_comments.get() is not None:
                        # Style Comment Form buttons for current user
                        CommentActionHandler().style_commentform_buttons(
                                                            self, post, user)

                # print "BEFORE render, main_user_msgs is: %s" % main_user_msgs
                # Get Current Date Time
                current_date_time = datetime.datetime.utcnow()

                # Render our page
                self.render("welcome.html", username=username,
                            user_logged_posts=user_logged_posts,
                            all_posts=all_posts, main_user_msgs=main_user_msgs,
                            msg_type=msg_type,
                            current_date_time=current_date_time)
        else:
            print "We don't have a cookie set yet!"

        # Mark any Error msgs as viewed if applicable
        if self.get_main_msg is not None and self.get_main_msg != "":
            self.session["messages_viewed"] = 1
            self._set_jinja_variable_session()

        # Redirect to signup page if USER is invalid or NOT Logged in
        if user_logged_in is False or user_valid is False:
            self.redirect("/blog/signup")


class BlogRouter(Handler):
    """
    Catch-All Blog Router
    """
    def get(self):
        self.redirect("/blog")


class LetsEncryptHandler(Handler):
    """
    See: http://blog.seafuj.com/lets-encrypt-on-google-app-engine
    -- as reference for setting up LetsEncrypt certificates
    For renewals run: 
    sudo certbot certonly --manual -d domain.com -d www.domain.com
    """
    def get(self, challenge):
        self.response.headers['Content-Type'] = 'text/plain'
        responses = {
            '[challenge 1]': '[response 1]',
            '[challenge 2]': '[response 2]'
        }
        self.response.write(responses.get(challenge, ''))


SECRET_KEY = Hasher().get_secret_key()

config = {}
config['webapp2_extras.sessions'] = {
    'secret_key': '%s' % SECRET_KEY,
}
config['TEMPLATES_AUTO_RELOAD'] = True

app = webapp2.WSGIApplication([
    ('/blog', Blog),
    ('/blog/welcome', Welcome),
    ('/blog/signup', UserSignup),
    ('/blog/login', Login),
    ('/blog/logout', Logout),
    ('/blog/newpost', NewPostHandler),
    ('/blog/*', BlogRouter),
    ('/*', BlogRouter),
    webapp2.Route(r'/blog/<post_id:\d+>', handler=PostHandler, name='post'),
    webapp2.Route(r'/blog/<post_id:\d+>/comment',
                  handler=CommentActionHandler, name='newcomment'),
    webapp2.Route(r'/blog/<post_id:\d+>/comment/<comment_id:\d+>',
                  handler=CommentActionHandler, name='comment'),
    ('/.well-known/acme-challenge/([\w-]+)', LetsEncryptHandler),
], config=config, debug=True)
