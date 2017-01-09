import logging
from flask import Flask, render_template, url_for, request, redirect, flash, jsonify
from database_contract import Restaurant, MenuItem, User, use_key
from lotsofmenus import populateDB
from utility import *

# OAUTH2
from flask import session as login_session
import random, string
from apiclient import discovery
import httplib2
from oauth2client import client

import json
from flask import make_response


root_dir = '/restaurants'

app = Flask(
    __name__,
    static_url_path=root_dir,
    static_folder='static',
    template_folder='templates'
)
app.secret_key = getSecretKey()


#
# Restaurants
@app.route(root_dir)
@app.route(root_dir + '/')
@nocache
def mainPage():
    restaurants = list()
    restaurantQuery = Restaurant.all()
    restaurantQuery.order("created")

    for restaurant in restaurantQuery:
        r = dict()
        r['id'] = restaurant.key().id()
        r['name'] = restaurant.name
        r['courses'] = getMenuItems(restaurant)
        r['avgPrice'] = render_price(r['courses'])
        r['user_id'] = restaurant.user.key().id()

        restaurants.append(r)

    return render_template('front.html', restaurants=restaurants, login_session=login_session)


@app.route('/restaurants/new/', methods=['GET', 'POST'])
def restaurantNew():
    """ """
    if 'user_id' not in login_session:
        flash("You are not signed in", "user-error")
        return render_template('restaurantNew.html', login_session=login_session)

    if request.method == 'POST':
        name = request.form['name']
        user_id = login_session['user_id']
        user = User.get_by_id(user_id)

        if name:
            newRestaurant = Restaurant(name=name, user=user, parent=use_key())
            newRestaurant.put()

            flash("New Restaurant Created", "restaurant")
            return redirect(url_for('mainPage'))
    else:
        return render_template('restaurantNew.html', login_session=login_session)


@app.route('/restaurants/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
def restaurantEdit(restaurant_id):
    """ """
    restaurant = Restaurant.get_by_id(restaurant_id)

    if not restaurant:
        return redirect(url_for('mainPage'))

    if login_session.get('user_id') != restaurant.user.key().id():
        flash("Permission denied", "user-error")
        return redirect(url_for('mainPage'))

    if request.method == 'POST':
        name = request.form['name']
        if name:
            restaurant.name = name
            restaurant.put()

            flash('Restaurant Successfully Edited', 'restaurant')
            return redirect(url_for('mainPage'))
    else:
        return render_template('restaurantEdit.html', restaurant=restaurant, login_session=login_session)


@app.route('/restaurants/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
def restaurantDelete(restaurant_id):
    """ """
    restaurant = Restaurant.get_by_id(restaurant_id)

    if not restaurant:
        return redirect(url_for('mainPage'))

    if login_session.get('user_id') != restaurant.user.key().id():
        flash("Permission denied", "user-error")
        return redirect(url_for('mainPage'))

    menuItems = MenuItem.all()
    menuItems.filter("restaurant = ", restaurant.key())

    if request.method == 'POST':
        for menuItem in menuItems:
            menuItem.delete()

        restaurant.delete()

        flash('Restaurant Successfully Deleted', 'restaurant')
        return redirect(url_for('mainPage'))
    else:
        return render_template('restaurantDelete.html', restaurant=restaurant, login_session=login_session)


@app.route('/restaurants/JSON/')
def restaurantJson():
    """ """
    restaurants = Restaurant.all()
    return jsonify(Restaurants=[restaurant.serialize for restaurant in restaurants])


#
# Menus
@app.route('/restaurants/<int:restaurant_id>/')
@app.route('/restaurants/<int:restaurant_id>/menu/')
@nocache
def restaurantMenu(restaurant_id):
    """ List all the menu for specific restaurant """

    restaurant = Restaurant.get_by_id(restaurant_id)

    if not restaurant:
        return redirect(url_for('mainPage'))

    menuItems = getMenuItems(restaurant)
    authors = getMenuCreators(restaurant)

    return render_template("restaurantMenu.html", restaurant=restaurant, menuItems=menuItems,
                           login_session=login_session, authors=authors)


@app.route('/restaurants/<int:restaurant_id>/menu/new/', methods=['GET', 'POST'])
def restaurantMenuItemNew(restaurant_id):
    """ List all the menu for specific restaurant """

    restaurant = Restaurant.get_by_id(restaurant_id)

    if not restaurant:
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))


    if 'user_id' not in login_session:
        flash("You are not signed in", "user-error")
        return render_template('menuItemNew.html', restaurant=restaurant, login_session=login_session)


    if request.method == 'POST':
        if request.form['name']:
            user = User.get_by_id(login_session['user_id'])
            newItem = MenuItem(name=request.form['name'], description=request.form['description'],
                               price=float(request.form['price']), course=request.form['course'], restaurant=restaurant,
                               parent=use_key(), user=user)
            newItem.put()

            flash('Menu Item Created', 'menu')
            return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))
    else:
        return render_template('menuItemNew.html', restaurant=restaurant, login_session=login_session)


@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/edit/', methods=['GET', 'POST'])
def restaurantMenuItemEdit(restaurant_id, menu_id):
    """ List all the menu for specific restaurant """

    restaurant = Restaurant.get_by_id(restaurant_id)
    menuItem = MenuItem.get_by_id(menu_id)

    if not (restaurant and menuItem):
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))

    if login_session.get('user_id') != menuItem.user.key().id():
        flash("Permission denied", "user-error")
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))

    if request.method == 'POST':
        if request.form['name']:
            menuItem.name = request.form['name']
        if request.form['description']:
            menuItem.description = request.form['description']
        if request.form['price']:
            menuItem.price = float(request.form['price'])
        if request.form['course']:
            menuItem.course = request.form['course']

        menuItem.put()

        flash('Menu Item Successfully Edited', 'menu')
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))
    else:
        return render_template('menuItemEdit.html', menuItem=menuItem, restaurant=restaurant, login_session=login_session)


@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/delete/', methods=['GET', 'POST'])
def restaurantMenuItemDelete(restaurant_id, menu_id):
    """ List all the menu for specific restaurant """

    restaurant = Restaurant.get_by_id(restaurant_id)
    menuItem = MenuItem.get_by_id(menu_id)

    if not (restaurant and menuItem):
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))

    if login_session.get('user_id') != menuItem.user.key().id():
        flash("Permission denied", "user-error")
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))

    if request.method == 'POST':
        menuItem.delete()

        flash('Menu Item Successfully Deleted', 'menu')
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))
    else:
        return render_template('menuItemDelete.html', menuItem=menuItem, restaurant=restaurant, login_session=login_session)


@app.route('/restaurants/<int:restaurant_id>/menu/JSON/')
def restaurantMenuJson(restaurant_id):
    """ List all the menu for specific restaurant """

    restaurant = Restaurant.get_by_id(restaurant_id)

    if not restaurant:
        return redirect(url_for('mainPage'))

    menuItems = MenuItem.all()
    menuItems.filter("restaurant = ", restaurant.key())

    return jsonify(MenuItems=[menuItem.serialize for menuItem in menuItems])


@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/JSON/')
def restaurantMenuItemJson(restaurant_id, menu_id):
    """ List all the menu for specific restaurant """

    restaurant = Restaurant.get_by_id(restaurant_id)
    menuItem = MenuItem.get_by_id(menu_id)

    if not (restaurant and menuItem):
        return redirect(url_for('mainPage'))

    return jsonify(MenuItem=[menuItem.serialize])


@app.route('/restaurants/lotsofmenus/')
def lotsofmenus():

    q = Restaurant.all()
    if q.count() > 0:
        return "Database already exists"
    else:
        populateDB()
        return "Added menu successfully"

#
# OAuth


# Create anti-forgery state token
@app.route('/restaurants/login/')
def login():

    # if 'username' in login_session:
    #     flash("You already logged in as %s" % login_session['username'], "user")
    #     return redirect(url_for('mainPage'))

    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Google login
APPLICATION_NAME = "Restaurant Menu Application"


@app.route('/restaurants/gconnect', methods=['POST'])
def gconnect():

    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Receive auth_code by HTTPS POST
    auth_code = request.data

    # Set path to the Web application client_secret_*.json file you downloaded from the
    # Google API Console: https://console.developers.google.com/apis/credentials
    CLIENT_SECRET_FILE = 'restaurants/g_client_secrets.json'

    # Exchange auth code for access token, refresh token, and ID token
    credentials = client.credentials_from_clientsecrets_and_code(
        CLIENT_SECRET_FILE,
        ['https://www.googleapis.com/auth/userinfo.profile', 'profile', 'email'],
        auth_code)
    profile_id = credentials.id_token['sub']

    # Check if user is already connected
    stored_credentials = login_session.get('credentials')
    stored_profile_id = login_session.get('profile_id')
    if stored_credentials is not None and profile_id == stored_profile_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials.to_json()
    login_session['profile_id'] = profile_id

    # Call Google API to retrieve user info
    http_auth = credentials.authorize(httplib2.Http())
    users_service = discovery.build('oauth2', 'v2', http=http_auth)
    user_info = users_service.userinfo().get().execute()

    # Store the user info in the session for later use.
    login_session['name'] = user_info['name']
    login_session['first_name'] = user_info['given_name']
    login_session['picture'] = user_info['picture']
    login_session['email'] = user_info['email']
    login_session['access_token'] = credentials.access_token

    # Add provider to session
    login_session['provider'] = 'google'

    # Local Permission
    user_id = getUserByProfileID(login_session['profile_id'])
    if not user_id:
        user_id = createUser(login_session)
        flash("You are now logged in as %s" % login_session['name'], "user")
    else:
        flash("Welcome back %s" % login_session['name'], "user")

    login_session['user_id'] = user_id

    # Output
    output = ''
    output += '<h1>Welcome, '
    output += login_session['name']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    return output


@app.route('/restaurants/gdisconnect/')
def gdisconnect():
    # Only disconnect a connected user.
    credentials_json = login_session.get('credentials')
    if credentials_json is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    try:
        credentials = client.OAuth2Credentials.from_json(credentials_json)
        credentials.revoke(httplib2.Http())
        response = make_response(
            json.dumps('Success.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    except:
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/restaurants/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = request.data

    # generate a long-lived token from a short-lived token
    # https://developers.facebook.com/docs/facebook-login/access-tokens/expiration-and-extension
    app_id = json.loads(open('restaurants/fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(
        open('restaurants/fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # strip expire tag from access token
    token = result.split("&")[0]

    # Get User Profile
    url = "https://graph.facebook.com/v2.8/me?fields=id,name,email,first_name,last_name&" + token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Retrieve data from Json
    data = json.loads(result)

    # Store into session for later use
    login_session['provider'] = 'facebook'
    login_session['name'] = data["name"]
    login_session['first_name'] = data["first_name"]
    login_session['email'] = data["email"]
    login_session['profile_id'] = data["id"]
    login_session['access_token'] = token.split("=")[1]

    # Get high photo with desired size (200px by 200px)
    url = 'https://graph.facebook.com/v2.8/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['picture'] = data["data"]["url"]

    # Local Permission
    user_id = getUserByProfileID(login_session['profile_id'])
    if not user_id:
        user_id = createUser(login_session)
        flash("You are now logged in as %s" % login_session['name'], "user")
    else:
        flash("Welcome back %s" % login_session['name'], "user")

    login_session['user_id'] = user_id

    # Output
    output = ''
    output += '<h1>Welcome, '
    output += login_session['name']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    return output


@app.route('/restaurants/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['profile_id']
    # The access token must be included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Logout user
def clearLoginSession():
    # Google
    login_session.pop('credentials', None)
    # Facebook

    # Common
    login_session.pop('access_token')
    login_session.pop('name', None)
    login_session.pop('first_name', None)
    login_session.pop('email', None)
    login_session.pop('picture', None)
    login_session.pop('user_id', None)
    login_session.pop('provider', None)
    login_session.pop('profile_id', None)


@app.route('/restaurants/logout/')
def logout():
    # Note: Log out don't revoke token
    if 'user_id' in login_session:
        clearLoginSession()
        flash("You have successfully been logged out.", "user")
        return redirect(url_for('mainPage'))
    else:
        flash("You were not logged in", "user")
        return redirect(url_for('mainPage'))


# Disconnect based on provider
@app.route('/restaurants/disconnect/')
def disconnect():
    if 'provider' in login_session:
        # Revoke token
        if login_session['provider'] == 'google':
            gdisconnect()
        if login_session['provider'] == 'facebook':
            fbdisconnect()

        clearLoginSession()
        flash("You have successfully been disconnectted.", "user")
        return redirect(url_for('mainPage'))
    else:
        flash("You were not logged in", "user")
        return redirect(url_for('mainPage'))


# Local Permission
def createUser(login_session):
    newUser = User(profile_id=login_session['profile_id'],
                   name=login_session['name'],
                   email=login_session['email'],
                   picture=login_session['picture'],
                   parent=use_key())
    user_key = newUser.put()
    return user_key.id()


def getUserByProfileID(profile_id):
    user = User.all()
    user.filter("profile_id = ", profile_id)

    if user.get():
        return user.get().key().id()
    return None


@app.errorhandler(500)
def server_error(e):
    # Log the error and stacktrace.
    logging.exception('An error occurred during a request.')
    return 'An internal error occurred.', 500

if __name__ == '__main__':
    app.debug = False
    app.run()
