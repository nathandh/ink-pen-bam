"""
Ink-Pen-Bam data MODELS module

ver 0.1 initial: 04/19/2017
"""

# Google App Engine DataStore
from google.appengine.ext import db
# Handler from 'blog' for custom renderered content
from ipbbase import Handler


class User(db.Model):
    """
    USER App Engine Entity (Model) for persistance
    """
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()
    salt = db.StringProperty(required=True)


class Post(db.Model):
    """
    POST Google App Engine Entity (Model) for persistance
    """
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created_by = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_content = self.content.replace('\n', '<br />')
        return Handler().render_str("post.html", post=self)

    def render_short(self):
        # Shorten post content displayed (Except for permalink
        # pages that use render() above)
        content_max = 225

        short_content = self.content.replace('\n', '<br />')
        permalink = "/blog/%s" % self.key().id()
        more_post_link = "&nbsp;<a href='%s'>...View More...</a>" % permalink
        if len(short_content) > content_max:
            short_content = short_content[:content_max] + more_post_link

        self._rendershort_content = short_content
        return Handler().render_str("post-short.html", post=self)


class Like(db.Model):
    """
    LIKE GAE Entity (Model) for persistance
    """
    # 'likes' Collection, as we can have MANY likes for 1 post
    post = db.ReferenceProperty(Post,
                                collection_name='post_likes')

    # likewise, we can have MANY likes for 1 user
    user = db.ReferenceProperty(User,
                                collection_name='user_likes')

    liked = db.StringProperty(choices=('true', 'false'), required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


class Comment(db.Model):
    """
    COMMENT GoogleAppEngine (Model) for persistance
    """
    post = db.ReferenceProperty(Post,
                                collection_name='post_comments')

    user = db.ReferenceProperty(User,
                                collection_name='user_comments')

    comment_parent = db.SelfReferenceProperty(required=False, default=None,
                                              collection_name='replies')

    comment = db.TextProperty(required=True)
    created_by = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self, post):
        self._render_content = self.comment.replace('\n', '<br />')
        return Handler().render_str("comment.html", comment=self, post=post)

    def render_single(self):
        single_content = self.comment.replace('\n', '<br />')
        self._render_single = single_content
        return Handler().render_str("comment-single-reply.html", comment=self)
