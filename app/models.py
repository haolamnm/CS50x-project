import os
from dotenv import load_dotenv
from app.extensions import db
from datetime import datetime, timezone
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer


load_dotenv()


class User(db.Model):
	"""
	User model.

	Attributes:
	- A user has an email, password, created date, OAuth provider and OAuth ID.

	Relationships:
	- A user has many tasks.
	- A user has many pomodoro sessions.

	Methods:
	- get_token: Generate token for user authentication.
	- verify_token: Verify token and return user based on user id. If token is invalid, return None.
	"""
	__tablename__ = 'users'

	id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
	email = db.Column(db.String(100), nullable=False, unique=True)
	password = db.Column(db.String(255), nullable=True, unique=False)
	create_time = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False, unique=False)
	oauth_provider = db.Column(db.String(50), nullable=True, unique=False, default='local')
	oauth_id = db.Column(db.String(255), nullable=True, unique=False)

	# Relationships
	tasks = db.relationship('Task', backref='user', lazy=True)
	pomodoro_sessions = db.relationship('PomodoroSession', backref='user', lazy=True)


	def __init__(self, email: str, password: str, oauth_provider: str = 'local', oauth_id: str = None) -> None:
		"""
		Create a new user.

		:param email: The email.
		:param password: The password.
		:param oauth_provider: The OAuth provider.
		:param oauth_id: The OAuth ID.
		:return: None
		"""
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
		return f'<User #{self.id}: {self.email} - {self.oauth_provider}>'


class Task(db.Model):
	"""
	Task model.

	Attributes:
	- A task has a title, description, created date.

	Relationships:
	- A task belongs to a user.
	- A task has many pomodoro sessions

	Methods:
	- None
	"""
	__tablename__ = 'tasks'

	id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=False)
	title = db.Column(db.String(100), nullable=False, unique=False)
	description = db.Column(db.String(255), nullable=True, unique=False)
	create_time = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False, unique=False)

	# Relationships
	pomodoro_sessions = db.relationship('PomodoroSession', backref='task', lazy=True)


class PomodoroSession(db.Model):
	"""
	Pomodoro session model.

	Attributes:
	- A pomodoro session has a task ID, user ID, start time, end time, duration, interupted, completed.

	Relationships:
	- A pomodoro session belongs to a task.
	- A pomodoro session belongs to a user.
	- A user can view all their Pomodoro sessions either directly or indirectly through a task.

	Methods:
	- None
	"""
	__tablename__ = 'pomodoro_sessions'

	id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
	task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False, unique=False)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=False)
	start_time = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False, unique=False)
	end_time = db.Column(db.DateTime, nullable=True, unique=False)
	duration = db.Column(db.Integer, default=50, nullable=False, unique=False)
	interupted = db.Column(db.Boolean, default=False, nullable=False, unique=False)
	completed = db.Column(db.Boolean, default=False, nullable=False, unique=False)


if __name__ == '__main__':
	pass
