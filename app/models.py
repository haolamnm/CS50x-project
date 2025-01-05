import os
from dotenv import load_dotenv
from app.extensions import db
from datetime import datetime, timezone
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer


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

	def __init__(self, username: str, email: str, password: str, oauth_provider: str = 'local', oauth_id: str = None) -> None:
		"""
		Create a new user.

		:param username: The username.
		:param email: The email.
		:param password: The password.
		:param oauth_provider: The OAuth provider.
		:param oauth_id: The OAuth ID.
		:return: None
		"""
		self.username = username
		self.email = email
		self.password = password
		self.oauth_provider = oauth_provider
		self.oauth_id = oauth_id

	def get_token(self) -> str:
		"""
		Generate token for user authentication.

		:return: The token.
		"""
		serializer = Serializer(
			secret_key=os.getenv('SECRET_KEY'),
		)
		return serializer.dumps({'user_id': self.id})

	@staticmethod
	def verify_token(token: str, max_age: int = 300) -> 'User':
		"""
		Verify token and return user based on user id. If token is invalid, return None.

		:param token: The token to verify.
		:param max_age: The lifetime of the token in seconds.
		:return: User if token is valid, otherwise None.
		"""
		serializer = Serializer(os.getenv('SECRET_KEY'))
		try:
			user_id = int(serializer.loads(s=token, max_age=max_age)['user_id'])
		except:
			return None
		return User.query.get(user_id)

	def __repr__(self) -> str:
		"""
		Return a string representation of the user.

		:return: The string representation.
		"""
		return f'<User #{self.id}: {self.username} - {self.email} - {self.oauth_provider}>'


if __name__ == '__main__':
	pass
