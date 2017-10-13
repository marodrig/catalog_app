# Catalog Web Application

Web application using Flask for backend portion and Foundation CSS for the styling.
The application is a basic catalog of items and includes login using Google's oauth2.

## Requirements

- Flask: web development framework.
- Google user account for oauth2.

## Usage

We need to populate the database with data, in order to do so we need to run the followin command:

'''cmd
python populate_db.py
'''

After that we can run the application by the following command:

'''cmd
python views.py
'''

Access the application by going to:

http://localhost:8080/

### JSON API

This application has a JSON API that can access individual items, all items and all categories of the catalog.

#### Get all items

Once the user user is authenticated by login using Google, access a list of all items by typing the following in you browser:

http://localhost:8080/api/v1/items

#### Get individual item

User needs to be logged in and type the following in the browser:

http://localhost:8080/api/v1/items/[__item\_id__]

Where__item\_id__ is the id for the item we want to access.

#### Get all categories in our catalog

User needs to be logged in and type the following in the browser:

http://localhost:8080/api/v1/categories/

## License
