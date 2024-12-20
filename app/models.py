from datetime import datetime
from app import db

class User(db.Model):
	__tablename__ = 'users'

	id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
	username = db.Column(db.String(100), nullable=False, unique=True)
	email = db.Column(db.String(100), nullable=False, unique=True)
	password = db.Column(db.String(255), nullable=False, unique=False)
	created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, unique=False)

	def __init__(self, username, email, password):
		self.username = username
		self.email = email
		self.password = password

	def __repr__(self):
		return '<User %r>' % self.username

	# def serialize(self):
	# 	return {
	# 		'id': self.id,
	# 		'username': self.username,
	# 		'email': self.email,
	# 		'created': self.created
	# 	}
