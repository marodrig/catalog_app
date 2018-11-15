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

### Cloning repository:

You can clone this repository by using git:

```console
git clone https://github.com/marodrig/catalog_app
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

#### Status Codes

| Code  | Meaning  |
|-------|----------|
|  200  | OK       |

#### End Points

| end-point URL |      Action  |  Response |
|---------------|--------------|-----------|
| _/api/v1/items_ | Get an array of all items| {<br>items:[{<br>'id':1,<br>'category_name':"Sports',<br>'name':"Soccer Ball",<br> 'description':"Required to play soccer.",<br>'date_created':"2015-07-04",<br>'price':"50.0",<br>},<br>{}]}|
| _/api/v1/items/{int:item_id}_ | Get individual item | {<br>'id':1,<br>'category_name':"Sports',<br>'name':"Soccer Ball",<br> 'description':"Required to play soccer.",<br>'date_created':"2015-07-04",<br>'price':"50.0",<br>} |
| _/api/v1/categories/_ | Get all categories in catalog | {<br>categories:[{<br>'id':1,<br>'']} |


## Tests

## FAQ

## Contributing

## Credits

## License

[LICENSE](LICENSE)
