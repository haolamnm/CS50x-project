import os

class Config:
	SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24))

	# TODO: Change this to my own database URI after deployment
	SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://postgres.ymroedmidxjknaxpcaur:6SfSsoJ3rnowKMIm@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres?sslmode=require')
	SQLALCHEMY_TRACK_MODIFICATIONS = False

	# Flask-Session configuration
	SESSION_TYPE = 'filesystem'
	SESSION_FILE_DIR = os.path.join(os.getcwd(), 'flask_session')
	SESSION_PERMANENT = False
