from database_contract import Restaurant, MenuItem, User
from flask import make_response
from functools import wraps, update_wrapper
from datetime import datetime


def getMenuItems(restaurant):
    return [queryMenuItems(restaurant, "Appetizer"),
     queryMenuItems(restaurant, "Entree"),
     queryMenuItems(restaurant, "Dessert"),
     queryMenuItems(restaurant, "Beverage")]


def queryMenuItems(restaurant, term):
    q = MenuItem.all()
    q.filter("restaurant =", restaurant.key())
    q.order("name")
    return term, q.filter("course =", term).fetch(limit=None)


def getMenuCreators(restaurant):
    """ Return sorted list of tuples (Author, count) """
    menu = MenuItem.all()
    menu.filter("restaurant =", restaurant)

    creators = dict()
    for m in menu:
        user_id = m.user.key().id()
        count = creators.get(user_id, 0)
        creators[user_id] = count + 1

    lists = list()
    for key, value in creators.iteritems():
        user = User.get_by_id(key)
        lists.append((user.name, value, user.picture))

    return sorted(lists, key=lambda x: x[1], reverse=True)


def render_price(coursesList):
    prices = 0.
    count = 0
    for _, courses in coursesList:
        for course in courses:
            prices += course.price
            count += 1

    if count == 0:
        return "$"

    avg = prices / count

    if avg < 5.:
        return "$"
    elif avg < 10:
        return "$$"
    else:
        return "$$$"


def nocache(view):
    """ No cache, add @nocache decorator  """

    @wraps(view)
    def no_cache(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Last-Modified'] = datetime.now()
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

    return update_wrapper(no_cache, view)


def getSecretKey():
    return 'l\xd2\xfbv_<\xf2\xfd}+A6*\x19F\x1c\xa7\xd1\x8d\x07\x83T\xb7\x8f'
