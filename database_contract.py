from google.appengine.ext import db


def use_key(group='default'):
    return db.Key.from_path('restaurants', group)


class User(db.Model):

    profile_id = db.StringProperty(required=True)
    name = db.StringProperty(required=True)
    email = db.EmailProperty()
    picture = db.LinkProperty()

    @classmethod
    def get_by_id(cls, ids, parent=None, **kwargs):
        return super(User, cls).get_by_id(ids, parent=use_key(), **kwargs)


class Restaurant(db.Model):
    name = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user = db.ReferenceProperty(User, required=True)

    @classmethod
    def get_by_id(cls, ids, parent=None, **kwargs):
        return super(Restaurant, cls).get_by_id(ids, parent=use_key(), **kwargs)

    @property
    def serialize(self):
        """ Returns object data in easily serializable format """
        return {
            'id': self.key().id(),
            'name': self.name,
            'created': self.created,
            'last-modified': self.last_modified
        }


class MenuItem(db.Model):

    name = db.StringProperty(required=True)
    description = db.StringProperty()
    price = db.FloatProperty()
    course = db.StringProperty()
    restaurant = db.ReferenceProperty(Restaurant, required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user = db.ReferenceProperty(User, required=True)

    @classmethod
    def get_by_id(cls, ids, parent=None, **kwargs):
        return super(MenuItem, cls).get_by_id(ids, parent=use_key(), **kwargs)

    @property
    def serialize(self):
        """ Returns object data in easily serializable format """
        return {
            'id': self.key().id(),
            'name': self.name,
            'description': self.description,
            'price': "$" + str(self.price),
            'course': self.course,
            'created': self.created,
            'last-modified': self.last_modified
        }