"""
ORM model information for the catalog web application
"""
import datetime
import hashlib
import os
import sys

from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import BadSignature, SignatureExpired
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy import (Column, DateTime, Float, ForeignKey, Integer, String,
                        create_engine)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()
secret_key = hashlib.sha256(os.urandom(1024)).hexdigest()


class User(Base):
    """
    Model of a user
    """
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), nullable=False)
    picture = Column(String(32))
    email = Column(String(64))
    pswd_hash = Column(String(64))
    def hash_password(self, password):
        """
        Creates a hash of the password
        """
        self.pswd_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        """
        Checks for password
        """
        return pwd_context.verify(password, self.pswd_hash)

    def generate_auth_token(self, expiration=600):
        """
        Creates and authentication token
        """
    	s = Serializer(secret_key, expires_in = expiration)
    	return s.dumps({'id': self.id })

    @staticmethod
    def verify_auth_token(token):
        """
        Verify auth token
        """
    	s = Serializer(secret_key)
    	try:
    		data = s.loads(token)
    	except SignatureExpired:
    		#Valid Token, but expired
    		return None
    	except BadSignature:
    		#Invalid Token
    		return None
    	user_id = data['id']


class Category(Base):
    """
    Model of a category in the catalog
    """
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(32), nullable=False)


    @property
    def serialize(self):
        """
        :param arg1:
        :type arg1:
        :return result:
        :type result:
        """
        return{'id': self.id,
                'name':self.name}


class Item(Base):
    """
    Model of an item of the catalog
    """
    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    user = relationship(User)
    created_by = Column(Integer, ForeignKey('user.id'))
    category = relationship(Category)
    category_id = Column(Integer, ForeignKey('category.id'))
    name = Column(String(32), nullable=False)
    description = Column(String(128))
    date_created = Column(DateTime, default=datetime.datetime.utcnow)
    price = Column(Float)


    @property
    def serialize(self):
        """
        :param arg1:
        :type arg1:
        :return result:
        :type result:
        """
        return{
                'id':self.id,
                'category_name':self.category.name,
                'name':self.name,
                'description':self.description,
                'date_created':self.date_created,
                'price':self.price}


engine = create_engine('sqlite:///catalog_web_app.db')

Base.metadata.create_all(engine)
