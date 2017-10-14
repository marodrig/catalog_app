from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, Category, Item, User

engine = create_engine('sqlite:///catalog_web_app.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

test_user = User()
test_user.username = "admin"
test_user.email = "admin@catalog.com"
session.add(test_user)
session.commit()

new_category = Category()
new_category.name = "Soccer"
session.add(new_category)
session.commit()

new_item = Item()
new_item.name = "Abibas Predadors"
new_item.description = "I was created by admin and can't be deleted."
new_item.price = 120.59
new_item.category_id = new_category.id
new_item.created_by = test_user.id
session.add(new_item)
session.commit()
