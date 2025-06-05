# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask_login import UserMixin
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from flask_dance.consumer.storage.sqla import OAuthConsumerMixin
from apps.db import db
import datetime as dt

class Users(db.Model, UserMixin):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64), unique=True)
    email         = db.Column(db.String(64), unique=True)
    password      = db.Column(db.LargeBinary)
    bio           = db.Column(db.Text(), nullable=True)
    oauth_github  = db.Column(db.String(100), nullable=True)
    oauth_google  = db.Column(db.String(100), nullable=True)
    permissions   = db.Column(db.Text, nullable=True)  # JSON array of permissions
    is_active     = db.Column(db.Boolean, default=True)  # Added for freeze/unfreeze
    readonly_fields = ["id", "username", "email", "oauth_github", "oauth_google"]

    # Add relationship to ApiToken
    api_token = db.relationship('ApiToken', backref='user', uselist=False, foreign_keys='ApiToken.user_id')

    def __init__(self, **kwargs):
        for property, value in kwargs.items():
            if hasattr(value, '__iter__') and not isinstance(value, str):
                value = value[0]
            if property == 'password':
                from apps.authentication.util import hash_pass
                value = hash_pass(value)  # we need bytes here (not plain str)
            setattr(self, property, value)
    def __repr__(self):
        return str(self.username)
    @classmethod
    def find_by_email(cls, email: str) -> "Users":
        return cls.query.filter_by(email=email).first()
    @classmethod
    def find_by_username(cls, username: str) -> "Users":
        return cls.query.filter_by(username=username).first()
    @classmethod
    def find_by_id(cls, _id: int) -> "Users":
        return cls.query.filter_by(id=_id).first()
    @classmethod
    def find_by_api_token(cls, token: str) -> "Users":
        from apps.models.api_token import ApiToken
        api_token = ApiToken.query.filter_by(token=token, is_active=True).first()
        if api_token and (not api_token.expires_at or api_token.expires_at > dt.datetime.now(dt.timezone.utc)):
            return cls.query.get(api_token.user_id)
        return None
    def save(self) -> None:
        try:
            db.session.add(self)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            db.session.close()
            raise e
    def delete_from_db(self) -> None:
        try:
            db.session.delete(self)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            db.session.close()
            raise e

class OAuth(OAuthConsumerMixin, db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="cascade"), nullable=False)
    user = db.relationship(Users)
