"""
Ink-Pen-Bam BASE module
--includes 'template_dir' and 'jinja_env'
--definitions

ver 0.1 initial: 04/19/2017
"""

# Standard imports for environment
import os
import jinja2
import webapp2

# webapp2 simple sessions
from webapp2_extras import sessions

# Template directory specific
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


class Handler(webapp2.RequestHandler):
    """
    Handler class for app Helper Methods
    """
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
            if self.session.get('main_user_msgs') is None:
                print "No main_user_msgs set. Setting EMPTY value..."
                self.session['main_user_msgs'] = ""
        except LookupError:
            print "Error getting main msg in 'get_main_msg'..."
        finally:
            return self.session.get('main_user_msgs')

    def set_main_msg(self, msg):
        print "SET main msgs called..."
        # Set the msg
        try:
            self.session['main_user_msgs'] = msg
            print "Set main_user_msgs to: %s" % self.get_main_msg()
        except LookupError:
            print "Error setting 'main_user_msgs'..."

    def clear_main_msg(self):
        print "Clear main msgs called..."
        # Set MAIN User MSG Text to ""
        try:
            self.session['main_user_msgs'] = ""
        except LookupError:
            print "Session object doesn't exist yet...."

    def get_msg_type(self):
        print "GET msg type called..."
        # Get the current MSG type if available
        try:
            if self.session.get('msg_type') is None:
                print ("""No msg_type is set... Setting Empty Value
                       (will default to NOTICE type)...""")
                self.session['msg_type'] = ""
        except LookupError:
            print "Error getting msg type in 'get_msg_type'..."
        finally:
            return self.session.get('msg_type')

    def set_msg_type(self, msg_type):
        print "SET msg_type called..."
        # Set out type
        try:
            self.session['msg_type'] = msg_type
            print "Set msg_type to: %s" % self.get_msg_type()
        except LookupError:
            print "Error setting 'msg_type'...."

    def clear_msg_type(self):
        print "Clear msg_type called..."
        # Set Default msg_type
        try:
            self.session['msg_type'] = ""
        except LookupError:
            print "Session object doesn't exist yet..."

    def get_ref_source(self):
        """
        Gets the referrer source from headers, parses and returns it
        """
        source = None
        try:
            ref = self.request.referrer.split('http://')[1]
            first_slash = ref.find('/')
            source = ref[first_slash:]
        except LookupError:
            print "Can't parse HTTP Referrer."
        finally:
            print "Source retrieved was: %s" % source
            return source

    """
    Jinja ENV Specific
    """

    def _get_jinja_env(self):
        return jinja_env

    """
    Session MGMT Specific
    See the DOCs:
    http://webapp2.readthedocs.io/en/latest/api/webapp2_extras/sessions.html
    """

    def _get_jinja_variable_session(self):
        print "IN: Handler()._get_session()"
        # Get Jinja Global Environment Session object
        my_session = None
        try:
            # Uncomment for additional debugging
            # print "Curr cookie is: %s" % self.request.cookies.get('session')
            if self.request.cookies.get('session') is None:
                print ("""'session' COOKIE data does not exist yet...so
                       deleting any leftover Jinja Globals""")
                del jinja_env.globals['inkpenbam_session']

            my_session = jinja_env.globals.get('inkpenbam_session')
        except LookupError:
            print "No Jinja global 'session' exists to GET"
        finally:
            print "Exiting _get_session Request"
            return my_session

    def _set_jinja_variable_session(self):
        # SET Jinja Global Environment Session object
        # (Needs to be updated before used in a View)
        print "...attempting to set Session object"
        try:
            # self.response.delete_cookie('session', path='/')
            # self.response.set_cookie('session', path='/')
            jinja_env.globals['inkpenbam_session'] = self.session
            return self._get_jinja_variable_session()
        except LookupError:
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
