"""
Logic for rendering views of the catalog web application
"""
import os
import hashlib
import httplib2
import json
from flask import Flask, render_template, url_for, redirect, request
from flask import abort, g, make_response
from flask import session as login_session
from sqlalchemy.orm.exc import NoResultFound
from models import Base, Category, Item, User
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from oauth2client import client as oauth_client

app = Flask(__name__)

engine = create_engine('sqlite:///catalog_web_app.db')
DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/logout')
def logout():
    """
    """
    # Delete the user's profile and the credentials stored by oauth2.
    del login_session['profile']
    login_session.modified = True
    # oauth2.storage.delete()
    return redirect(request.referrer or '/')


@app.route('/oauth2callback')
def google_signin():
    """
    """
    flow = oauth_client.flow_from_clientsecrets('client_secret.json',
                                                scope=['openid', 'email'],
                                                message='Invalid key',
                                                redirect_uri=url_for('google_signin', _external=True))

    flow.params['access_type'] = 'offline'
    flow.params['include_granted_scopes'] = 'true'

    if 'code' not in request.args:
        state_tkn = hashlib.sha256(os.urandom(1024)).hexdigest()
        login_session['state'] = state_tkn
        auth_uri = flow.step1_get_authorize_url(state=login_session['state'])
        return redirect(auth_uri)

    code = request.args.get('code', '')
    if request.args.get('state', '') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    credentials = flow.step2_exchange(code)
    http = httplib2.Http()
    credentials.authorize(http)

    # resp, content = http.request()
    # if resp.status != 200:
    #     app.logger.error(
    #         "Error while obtaining user profile: \n%s: %s", resp, content)
    #     return None

    login_session['profile'] = credentials.id_token
    if not session.query(User).filter_by(email=login_session['profile']['email']).first():
        new_user = User(username=login_session['profile']['email'],email=login_session['profile']['email'])
        session.add(new_user)
        session.commit()
    logged_user = session.query(User).filter_by(email=login_session['profile']['email']).one()
    print("Current username: {}".format(logged_user.username))
    print("email: {}".format(login_session['profile']['email']))
    return redirect(url_for('get_categories'))


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


@app.route('/categories/create')
def create_category():
    """
    Create a new category
    """
    return render_template('createcategory.html')


@app.route('/categories/<int:category_id>/edit')
def edit_category(category_id):
    """
    Edit/update an existing category in database
    """
    return render_template('editcategory.html', category_id=category_id)


@app.route('/categories/<int:category_id>/delete')
def delete_category(category_id):
    """
    Delete a category from database
    """
    return render_template('deletecategory.html', category_id=category_id)


@app.route('/categories/<int:category_id>')
@app.route('/categories/<int:category_id>/items')
def show_category_items(category_id):
    """
    Get items for the given category

    :param category_id: Unique id of the category
    :return item_list: List of items
    """
    items_list = session.query(Item).filter_by(
        category_id=category_id).order_by('date_created').all()
    return render_template('items.html', items_list=items_list)


@app.route('/catalog/items/<int:item_id>')
def show_item(item_id):
    """
    Shows the item information
    """
    item = session.query(Item).filter_by(id=item_id).one()
    return render_template('item.html', item=item)


@app.route('/catalog/items/create', methods=['GET', 'POST'])
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
        session.commit()
        return redirect(url_for('get_categories'))
    return render_template('createitem.html', category_list=category_list)


@app.route('/catalog/items/<int:item_id>/edit', methods=['GET', 'POST'])
def edit_item(item_id):
    """
    Edit given item with item_id
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
        session.commit()
        return redirect(url_for('show_category_items', category_id=new_values['category_id']))
    category_list = session.query(Category).all()
    return render_template('edititem.html', item=item, category_list=category_list)


@app.route('/catalog/items/<int:item_id>/delete', methods=['GET', 'POST'])
def delete_item(item_id):
    """
    Delete an item by id
    """
    item = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        return redirect(url_for('show_category_items', category_id=item.category_id))
    return render_template('deleteitem.html', item=item)


if __name__ == '__main__':
    app.secret_key = hashlib.sha256(os.urandom(1024)).hexdigest()
    app.debug = True
    app.run(host='0.0.0.0', port=8080)
