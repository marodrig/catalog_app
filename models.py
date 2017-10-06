"""
ORM model information for the catalog web application
"""
import os
import sys
import datetime
from sqlalchemy import Column, ForeignKey, Integer, String, Float, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine


Base = declarative_base()


class User(Base):
    """
    """
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), nullable=False)
    picture = Column(String(32))
    email = Column(String(64))
    pswd_hash = Column(String(64))


class Category(Base):
    """
    """
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(32), nullable=False)


class Item(Base):
    """
    """
    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    category = relationship(Category)
    category_id = Column(Integer, ForeignKey('category.id'))
    name = Column(String(32), nullable=False)
    description = Column(String(128))
    date_created = Column(DateTime, default=datetime.datetime.utcnow)
    price = Column(Float)


engine = create_engine('sqlite:///catalog_web_app.db')

Base.metadata.create_all(engine)
