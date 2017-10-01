from flask import Flask


app = Flask(__name__)


@app.route('/')
@app.route('/categories')
def get_categories():
    """
    """
    return "All the categories."


@app.route('/categories/create')
def create_category():
    """
    """
    return "New category"


@app.route('/categories/<int:category_id>/edit')
def edit_category(category_id):
    """
    """
    return "Now editing category with id: {}".format(category_id)


@app.route('/categories/<int:category_id>/delete')
def delete_category(category_id):
    """
    """
    return "Deleting category with id: {}".format(category_id)


@app.route('/categories/<int:category_id>')
@app.route('/categories/<int:category_id>/items')
def show_category_items(category_id):
    """
    """
    return "These are the items for cateogry wiht id: {}".format(category_id)


@app.route('/categories/<int:category_id>/items/<int:item_id>')
def show_item(category_id, item_id):
    """
    """
    return "This is item with id {} and is in category with id {}".format(item_id, category_id)


@app.route('/categories/<int:category_id>/items/create')
def create_item(category_id):
    """
    """
    return "New item created."


@app.route('/categories/<int:category_id>/items/<int:item_id>/edit')
def edit_item(category_id, item_id):
    """
    """
    return "Editing item id: {} part of category id: {}".format(category_id, item_id)


@app.route('/categories/<int:category_id>/items/<int:item_id>/delete')
def delete_item(category_id, item_id):
    """
    """
    return "Deleted item id:{} part of category id: {}".format(category_id, item_id)


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=8080)
