# Catalog Web Application

Web application using Flask for backend portion and Foundation CSS for the styling.
The application is a basic catalog of items and includes login using Google's oauth2.

## What is the reason for this repo?

This repo was made as part of the Udacity nanodegree program. 

## Why should you care about this repo?

You want to learn about Flask and web development using Python.

## Table of Contents
<details>
  <summary>
    Click to expand ToC
  </summary>
  
  1. [Features](#features)
  2. [Installation](#installation--quick-start)
  3. [Built with](#built-with)
  4. [Usage](#usage)
  5. [API reference](#api-reference)
  6. [Tests](#tests)
  7. [FAQ](#faq)
  8. [Contributing](#contributing)
  9. [Credits](#credits)
  10. [Lincense](#license)
  </details>
  
## Features

## Installation & Quick Start

### Requirements

- Flask: web development framework.
- Google user account for oauth2.

### Cloning this repository using GIT

You can clone this repository by using git:

```console
git clone https://github.com/marodrig/catalog_app
```

### Using PIP to manage Python dependencies

PIP is a package manager for Python.  Included in this repo is a requirements.txt file with the requirements of the different packages used in this project.

You can simply use pip to install the necessary packages by navigating where the requirements.txt is found and typing:

```console
pip install -r requirements.txt 
```

## Built with

- [Flask](http://flask.pocoo.org/)
- [Python](https://www.python.org/)
- [pip](https://pypi.org/project/pip/)
- [Foundation CSS](https://foundation.zurb.com/)

## Usage

We need to populate the database with data, in order to do so we need to run the followin command:

```shell
python populate_db.py
```

After that we can run the application by the following command:

```shell
python views.py
```

Access the application by going to:
http://localhost:8080/

## API Reference

### JSON API

This application has a JSON API that can access individual items, all items and all categories of the catalog.

#### Rate Limit

N/A

#### Status Codes

| Code  |         Meaning                 |
|-------|---------------------------------|
| 200   | OK                              |
| 400   | Something user's end.           |
| 401   | Unauthorized                    |
| 403   | Frobidden                       |
| 500   | Something wrong on the server side of things. |

#### API End-Points and Response

| End-Point URI   |      Action                           |  Response                          |
|-----------------|---------------------------------------|------------------------------------|
| _/api/v1/items_ | Get an array of all items             | {<br> items:[{<br>  'id':1,<br>  'category_name':"Sports',<br>  'name':"Soccer Ball",<br>  'description':"Required to play soccer.",<br>'date_created':"2015-07-04",<br>'price':"50.0",<br>},<br>{}]}|
| _/api/v1/items/{int:item_id}_ | Get specific item       | {<br>'id':1,<br>'category_name':"Sports',<br>'name':"Soccer Ball",<br> 'description':"Required to play soccer.",<br>'date_created':"2015-07-04",<br>'price':"50.0",<br>} |
| _/api/v1/categories/_ | Get an array of all categories  | {<br>categories:[{<br>'id':1,<br>'name':"Sports",<br>},<br>{<br>'id':2,<br>'name':"Housing",<br>}]<br>} |


## Tests

## FAQ

## Contributing

## Credits

## License

[LICENSE](LICENSE)
