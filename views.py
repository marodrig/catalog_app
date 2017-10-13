"""
Views of the Flask catalog web application
"""
import hashlib
import json
import os
from functools import wraps

import httplib2
from flask import session as login_session
from flask import (Flask, abort, flash, g, jsonify, make_response, redirect,
                   render_template, request, url_for)
from itsdangerous import Signer
from models import Base, Category, Item, User
from oauth2client import client as oauth_client
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)

engine = create_engine('sqlite:///catalog_web_app.db')
DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.before_request
def csrf_protect():
    """
    Checks for a csrf token if the request is a POST.
    If not found, we abort with a 403 HTTP status

    :param request object:  Contains the request method/form
    :type Request:
    :return :
    :type :
    """
    if request.method == "POST":
        try:
            token = login_session.pop('_csrf_token')
        except KeyError:
            app.logger.error("Error: {}".format(KeyError))
        app.logger.debug("Token: {}".format(token))
        app.logger.debug("Form token: {}".format(
            request.form.get('_csrf_token')))
        if not token or token != request.form.get('_csrf_token'):
            abort(403)


@app.route('/logout')
def logout():
    """
    Deletes the user profile and credentials when logging out
    """
    if 'profile' in login_session:
        login_session.pop('profile')
    if '_session_id' in login_session:
        login_session.pop('_session_id')

    login_session.modified = True
    return redirect(request.referrer or '/')


@app.route('/oauth2callback')
def google_signin():
    """
    Call back for logging users using Googles oauth2 API
    Follows the flow given by the oauth client from Google
    """
    flow = oauth_client.flow_from_clientsecrets('client_secret.json',
                                                scope=[
                                                    'openid',
                                                    'email',
                                                    'profile'],
                                                message='Invalid key',
                                                redirect_uri=url_for('google_signin', _external=True))

    flow.params['access_type'] = 'offline'
    flow.params['include_granted_scopes'] = 'true'

    if 'code' not in request.args:
        state_tkn = hashlib.sha256(os.urandom(1024)).hexdigest()
        login_session['state'] = state_tkn
        auth_uri = flow.step1_get_authorize_url(state=login_session['state'])
        return redirect(auth_uri)

    if request.args.get('state', '') != login_session['state']:
        response = get_error_response('Invalid state parameter.', 401)
        return response

    auth_code = request.args.get('code')
    credentials = flow.step2_exchange(auth_code)

    if credentials.access_token_expired:
        response = get_error_response("Invalid token", 401)
        return response

    http_conn = httplib2.Http()
    credentials.authorize(http_conn)

    resp, content = http_conn.request(
        'https://www.googleapis.com/oauth2/v2/userinfo')
    if resp.status != 200:
        app.logger.error(
            "Error while obtaining user profile: \n%s: %s", resp, content)
        abort(400)

    login_session['profile'] = json.loads(content.decode('utf-8'))
    login_session.modified = True
    app.logger.debug("Profile Information: {}".format(
        login_session.get('profile')))

    user_email = login_session.get('profile').get('email')
    logged_user = authenticate_user(user_email)
    login_user(logged_user)
    flash("Logged in using google.")

    return redirect(url_for('get_categories'))


def get_error_response(msg, http_status):
    """
    Creates a response with the given message and http_status

    :param msg: Error message we show to the user
    :type msg: String
    :param http_status: HTTP status for the response object
    :type http_status: Integer
    :return response: http response with header 'application/json'
    :type response:  Response object
    """
    response = make_response(json.dumps(
        msg), http_status)
    response.headers['Content-Type'] = 'application/json'
    return response


def authenticate_user(user_email):
    """
    Looks for a User with the given email, and returns its User Object
    If not found, we create a new USER

    :param user_email: email received for google oauth2 login
    :type user_email: string
    :return logged_user:  authenticated user 
    :type logged_user: User Object
    """
    try:
        logged_user = session.query(User).filter_by(email=user_email).one()
    except NoResultFound:
        app.logger.erro("Error: {}".format(NoResultFound))
    if not logged_user:
        new_user = User(username=user_email, email=user_email)
        session.add(new_user)
        try:
            session.commit()
        except IntegrityError:
            app.loggg.erro("Error: {}".format(IntegrityError))
        logged_user = new_user
    return logged_user


def login_user(current_user):
    """
    Creates and assigns a session_id we can look for if the user is logged in

    :param current_user:
    :type current_user:  User Object
    :return result:  if session_id exists in the current user session cookie
    :type result: boolean
    """
    s = Signer('secret_key')
    login_session['_session_id'] = s.sign(str(current_user.id))
    return login_session.get('_session_id') is not None


def login_required(fnc):
    """
    Before rendering the view we check if the user is logged in

    :param fnc:
    :type fnc:
    :return result:
    :type result:
    """
    @wraps(fnc)
    def decorated_view(*args, **kwargs):
        """
        """
        if '_session_id' in login_session:
            s = Signer('secret_key')
            user_id = s.unsign(login_session.get('_session_id'))
            app.logger.debug('user_id: %s', user_id)
            try:
                user = session.query(User).filter_by(id=user_id).one()
            except NoResultFound:
                app.logger.error("Error: {}.".format(NoResultFound))
            if user:
                app.logger.debug('Authenticated user %s', user.username)
                # Success!
                return fnc(*args, **kwargs)
            else:
                flash("Session exists, but user does not exist (anymore)")
                return make_response('not authorized')
        else:
            flash("Please log in")
            return make_response('not authorized')
    return decorated_view


@app.route('/')
def get_categories():
    """
    Current categories and newest items
    This is displayed from the home location of the web app
    """
    category_list = session.query(Category).all()
    new_item_list = session.query(Item).order_by(
        'date_created').limit(10).all()
    return render_template('home.html', category_list=category_list, new_item_list=new_item_list)


@app.route('/categories/create', methods=['GET', 'POST'])
def create_category():
    """
    Create a new category
    """
    if request.method == 'POST':
        new_category = Category(name= request.form['name'])
        session.add(new_category)
        try:
            session.commit()
        except IntegrityError:
            app.logger.error("Error: {}".format(IntegrityError))
        flash("Added new category!")
        return redirect(url_for('get_categories'))
    category_list = session.query(Category).all()
    return render_template('createcategory.html', category_list=category_list)


@app.route('/categories/<int:category_id>')
@app.route('/categories/<int:category_id>/items')
def show_category_items(category_id):
    """
    Get items for the given category

    :param category_id: Unique id of the category
    :return item_list: List of items
    """
    category_list = session.query(Category).all()
    items_list = session.query(Item).filter_by(
        category_id=category_id).order_by('date_created').all()
    return render_template('items.html', items_list=items_list, category_list=category_list)


@app.route('/catalog/items/<int:item_id>')
def show_item(item_id):
    """
    Shows the item information
    """
    category_list = session.query(Category).all()
    item = session.query(Item).filter_by(id=item_id).one()
    return render_template('item.html', item=item, category_list=category_list)


@app.route('/catalog/items/create', methods=['GET', 'POST'])
@login_required
def create_item():
    """
    Create a new item for the catalog
    """
    category_list = session.query(Category).all()
    if request.method == 'POST':
        new_item = Item(name=request.form['name'],
                        description=request.form['description'],
                        category_id=request.form['category'],
                        price=request.form['price'])
        session.add(new_item)
        try:
            session.commit()
        except IntegrityError:
            app.logger.error("Error: {}".format(IntegrityError))
        flash("Created new catalog item.")
        return redirect(url_for('get_categories'))
    return render_template('createitem.html', category_list=category_list)


@app.route('/catalog/items/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    """
    Edits given item with item_id
    """
    new_values = dict()
    new_values['id'] = item_id
    qry_inst = session.query(Item).filter_by(id=item_id)
    item = qry_inst.one()
    if request.method == 'POST':
        if request.form['name']:
            new_values['name'] = request.form['name']
        if request.form['description']:
            new_values['description'] = request.form['description']
        if request.form['category']:
            new_values['category_id'] = request.form['category']
        if request.form['price']:
            new_values['price'] = request.form['price']
        qry_inst.update(new_values)
        try:
            session.commit()
        except IntegrityError:
            app.logger.error("Error: {}".format(IntegrityError))
        flash("Edited item from catalog.")
        return redirect(url_for('show_category_items', category_id=new_values['category_id']))
    category_list = session.query(Category).all()
    return render_template('edititem.html', item=item, category_list=category_list)


@app.route('/catalog/items/<int:item_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_item(item_id):
    """
    Delete an item by item_id
    """
    category_list = session.query(Category).all()
    item = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'POST':
        session.delete(item)
        try:
            session.commit()
        except IntegrityError:
            app.logger.error("Error: {}".format(IntegrityError))
        flash("Deleted item from catalog.")
        return redirect(url_for('show_category_items', category_id=item.category_id))
    return render_template('deleteitem.html', item=item, category_list=category_list)


@app.route('/api/v1/items/<int:item_id>', methods=['GET'])
@login_required
def item_json(item_id):
    """
    JSON API endpoint for accessing a specific item

    :param item_id: item id
    :type item_id: integer
    :return json: json object of the item 
    :type json: json
    """
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(item.serialize)


@app.route('/api/v1/items', methods=['GET'])
@login_required
def items_json():
    """
    JSON API endpoint for all items in the catalog

    :return json: json of all items in catalog
    :type json: json
    """
    items = session.query(Item).all()
    return jsonify(items_catalog=[item.serialize for item in items])


@app.route('/api/v1/categories', methods=['GET'])
@login_required
def categories_json():
    """
    JSON API endpoint for all categories of the catalog

    :return result: json of all categories
    :type result: json
    """
    categories = session.query(Category).all()
    return jsonify(category_list=[category.serialize for category in categories])


def generate_csrf_token():
    """
    Generates a csrf token used in forms

    :return csrf_token: value of the token
    :type csrf_token: string
    """
    if '_csrf_token' not in login_session:
        login_session['_csrf_token'] = hashlib.sha256(
            os.urandom(256)).hexdigest()
        login_session.modified = True
    return login_session['_csrf_token']


if __name__ == '__main__':
    app.jinja_env.globals['csrf_token'] = generate_csrf_token
    app.secret_key = hashlib.sha256(os.urandom(1024)).hexdigest()
    app.debug = True
    app.run(host='0.0.0.0', port=8080)
