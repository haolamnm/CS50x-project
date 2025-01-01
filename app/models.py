from datetime import datetime, timezone
from app import db


class User(db.Model):
	__tablename__ = 'users'

	id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
	username = db.Column(db.String(100), nullable=True, unique=True)
	email = db.Column(db.String(100), nullable=False, unique=True)
	password = db.Column(db.String(255), nullable=True, unique=False)
	created = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False, unique=False)
	oauth_provider = db.Column(db.String(50), nullable=True, unique=False, default='local')
	oauth_id = db.Column(db.String(255), nullable=True, unique=False)


class Activity(db.Model):
	__tablename__ = 'activities'

	id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
	goal = db.Column(db.String(100), nullable=False)
	created = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False, unique=False)
