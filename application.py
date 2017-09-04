from flask import Flask, render_template, request, redirect, jsonify, g, url_for, flash

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()
app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

# Connect to Database and create database session
engine = create_engine('sqlite:///categories.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
@app.route('/catalog/')
def catalog():
    '''
    Default landing page
    '''
    categories = session.query(Category).all()
    items = session.query(Item).join(Category).limit(15)
    if 'username' in login_session:
        return render_template(
            'catalog_log_in.html',
            categories=categories,
            items=items)
    else:
        return render_template(
            'catalog.html',
            categories=categories,
            items=items)


@app.route('/login/')
def login():
    '''
    '''
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    '''
    Call back method for google OAuth Log in
    '''
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'),
            200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if a user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    flash("you are now logged in as %s" % login_session['username'])
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gdisconnect')
def gdisconnect():
    '''
    Function to disconnect a user from OAuth.
    '''
    access_token = login_session.get('access_token')
    print access_token
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print result

    if result['status'] == '200':
        # Reset the user's sesson.
        login_session.clear()
        flash("You are logged out")
        return redirect(url_for('catalog'))
    else:
        # Disconnect the user regardless but let them know there was an error
        login_session.clear()
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Routes related to catalog
@app.route('/catalog/<category>/items/')
def show_items(category):
    '''
    Function that displays all the items of a category
    It also looks for the names of all categories to list them

    '''
    this_category = session.query(Category).filter_by(name=category).first()
    if this_category is None:
        return "Error Category Not Found"
    categories = session.query(Category).all()
    items = session.query(Item).filter_by(category_id=this_category.id).limit(15)

    if 'username' in login_session:
        return render_template(
            'show_category_log_in.html',
            this_category=this_category,
            items=items,
            all_categories=categories)
    else:
        return render_template(
            'show_category.html',
            this_category=this_category,
            items=items,
            all_categories=categories)


@app.route('/catalog/<category>/<item>/')
def show_single_item(item, category):
    '''
    Shows a single item and its description.
    Will allow a user to edit and delete a item
    '''
    category_id = session.query(Category).filter_by(name=category).first().id
    this_item = session.query(Item).filter_by(name=item).first()

    if this_item is None:
        return "Cannot find this " + item + "in " + category

    this_item_category = session.query(Category).filter_by(id=this_item.category_id).first()
    if this_item_category.id is not category_id:
        return "Cannot find this" + item + "in" + category

    if 'username' in login_session:
        return render_template('item_log_in.html', this_item=this_item)
    else:
        return render_template('item.html', this_item=this_item)


@app.route('/catalog/<items>/edit/', methods=['GET', 'POST'])
def edit_item(items):
    '''
    Function to edit items. Will default to poulating fields with current item

    '''
    # First ensure user is logged in
    if 'username' not in login_session:
        return redirect(url_for('login'))
    item = session.query(Item).filter_by(name=items).first()
    category = session.query(Category).filter_by(id=item.category_id).first()
    # Check if item exists
    if item is None or category is None:
        return "Error Item not Found"

    # Next check who owns the item.
    if item.user_id is not login_session['user_id']:
        return "You do not have permission to edit this item"

    if request.method == 'POST':
        if request.form['name']:
            item.name = request.form['name']
        if request.form['description']:
            item.description = request.form['description']
        if request.form['category']:
            category_id = session.query(Category).filter_by(name=request.form['category']).first().id
            item.category_id = category_id
        flash('%s Successfully edited' % item.name)
        session.commit()
        return redirect(url_for('catalog'))
    else:
        return render_template('editItem.html', item=item, category=category)


@app.route('/catalog/<items>/delete/', methods=['GET', 'POST'])
def delete_item(items):
    '''
    Function to delete items. Will verify who owns item first
    '''
    if 'username' not in login_session:
        return redirect(url_for('login'))

    item = session.query(Item).filter_by(name=items).first()
    if item is None:
        return "Error Item not Found"

    if item.user_id is not login_session['user_id']:
        return "You do not have permission to delete this item"

    if request.method == 'POST':
        session.delete(item)
        flash('%s Successfully Deleted' % item.name)
        session.commit()
        return redirect(url_for('catalog'))
    else:
        return render_template('deleteItem.html', item=item)


@app.route('/new/', methods=['GET', 'POST'])
def create_item():
    '''
    Function to create items. Will check if a user is currently logged in.
    '''
    if 'username' not in login_session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # HARD CODE THE ID FOR NOW. I"LL ADD MORE USERS AND CHANGE THIS LATER
        # TODO
        category_id = session.query(Category).filter_by(name=request.form['category']).first().id
        obj = Item(
            name=request.form['name'],
            description=request.form['description'],
            category_id=category_id,
            user_id=login_session['user_id'])

        session.add(obj)
        session.commit()

        flash('New %s Item Successfully Created' % (obj.name))
        return redirect(url_for('catalog'))
    else:
        return render_template('newItem.html')


# Json endpoint
@app.route('/catalog.json')
def return_api():
    '''
    Function to return all items in all categories as a json oject
    '''
    # Make sure you are logged in
    if 'username' not in login_session:
        return redirect(url_for('login'))
    categories = session.query(Category).all()
    cat_list = [x.serialize for x in categories]
    for cat in cat_list:
        this_id = cat['id']
        items = [x.serialize for x in session.query(Item).filter_by(category_id=this_id).all()]
        cat['Item'] = items

    outer_wrapper = {}
    outer_wrapper['Category'] = cat_list
    return jsonify(outer_wrapper)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
