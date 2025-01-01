import os
from dotenv import load_dotenv


load_dotenv()


class Config:
	# Secret key configuration
	SECRET_KEY = os.getenv('SECRET_KEY')

	# Database configuration
	SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')
	SQLALCHEMY_TRACK_MODIFICATIONS = False

	# Session configuration
	SESSION_TYPE = 'filesystem'
	SESSION_FILE_DIR = os.path.join(os.getcwd(), 'flask_session')
	SESSION_PERMANENT = False
	SESSION_USER_SIGNER = True

	# OAuth configuration
	GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
	GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')


class TestConfig(Config):
	TESTING = True
	SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'


if __name__ == '__main__':
	print('--- Configurations ---')
	print(Config.SQLALCHEMY_DATABASE_URI)
	print(Config.SECRET_KEY)
	print(Config.SESSION_FILE_DIR)
