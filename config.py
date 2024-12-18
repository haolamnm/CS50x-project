import os

class Config:
	SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24))

	# TODO: Change this to my own database URI after deployment
	SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///db.sqlite')
	SQLALCHEMY_TRACK_MODIFICATIONS = False

	# Flask-Session configuration
	SESSION_TYPE = 'filesystem'
	SESSION_FILE_DIR = os.path.join(os.getcwd(), 'flask_session')
	SESSION_PERMANENT = False
