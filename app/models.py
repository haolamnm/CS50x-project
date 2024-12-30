from datetime import datetime
from app import db


class User(db.Model):
	__tablename__ = 'users'

	id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
	username = db.Column(db.String(100), nullable=False, unique=True)
	email = db.Column(db.String(100), nullable=False, unique=True)
	password = db.Column(db.String(255), nullable=False, unique=False)
	created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, unique=False)


class Activity(db.Model):
	__tablename__ = 'activities'

	id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
	goal = db.Column(db.String(100), nullable=False)
	created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, unique=False)
