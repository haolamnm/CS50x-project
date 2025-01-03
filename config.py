import os
import redis # type: ignore
from datetime import timedelta
from dotenv import load_dotenv


load_dotenv()


class Config:
	# Secret key configuration
	SECRET_KEY = os.getenv('SECRET_KEY')

	# Database configuration
	SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')
	SQLALCHEMY_TRACK_MODIFICATIONS = False

	# Session configuration
	SESSION_TYPE = 'redis'
	SESSION_PERMANENT = False
	SESSION_USER_SIGNER = True
	SESSION_KEY_PREFIX = 'session:'
	SESSION_REDIS = redis.StrictRedis(
		host=os.getenv('REDIS_HOST'),
		port=os.getenv('REDIS_PORT'),
		password=os.getenv('REDIS_PASSWORD'),
		ssl=True
	)
	PERMANENT_SESSION_LIFETIME = timedelta(weeks=1)

	# Google OAuth configuration
	GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
	GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')

	# Github OAuth configuration
	GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
	GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')

	# Mail configuration
	MAIL_SERVER = os.getenv('MAIL_SERVER')
	MAIL_PORT = int(os.getenv('MAIL_PORT'))
	MAIL_USE_TLS = True
	MAIL_USERNAME = os.getenv('MAIL_USERNAME')
	MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')


class DevelopmentConfig(Config):
	DEBUG = True
	SESSION_TYPE = 'filesystem'
	SESSION_FILE_DIR = os.path.join(os.getcwd(), 'flask_session')
	SESSION_REDIS = None


class TestConfig(Config):
	TESTING = True
	SESSION_TYPE = 'filesystem'
	SESSION_FILE_DIR = os.path.join(os.getcwd(), 'flask_session')
	SESSION_REDIS = None
	SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'


if __name__ == '__main__':
	pass
