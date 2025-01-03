import os
from datetime import datetime, timezone
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer
from app import db
from dotenv import load_dotenv


load_dotenv()


class User(db.Model):
	__tablename__ = 'users'

	id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
	username = db.Column(db.String(100), nullable=True, unique=True)
	email = db.Column(db.String(100), nullable=False, unique=True)
	password = db.Column(db.String(255), nullable=True, unique=False)
	created = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False, unique=False)
	oauth_provider = db.Column(db.String(50), nullable=True, unique=False, default='local')
	oauth_id = db.Column(db.String(255), nullable=True, unique=False)

	def get_token(self) -> str:
		serializer = Serializer(
			secret_key=os.getenv('SECRET_KEY'),
		)
		return serializer.dumps({'user_id': self.id})

	@staticmethod
	def verify_token(token: str, max_age: int=300) -> 'User':
		serializer = Serializer(os.getenv('SECRET_KEY'))
		try:
			user_id = int(serializer.loads(s=token, max_age=max_age)['user_id'])
		except:
			return None
		return User.query.get(user_id)

	def __repr__(self):
		return f'<User #{self.id}: {self.username} - {self.email} - {self.oauth_provider}>'


class Activity(db.Model):
	__tablename__ = 'activities'

	id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
	goal = db.Column(db.String(100), nullable=False)
	created = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False, unique=False)
