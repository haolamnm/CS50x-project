from flask import Flask
from flask_mail import Mail
from flask_migrate import Migrate
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth


db = SQLAlchemy()
mail = Mail()
oauth = OAuth()
session = Session()
migrate = Migrate()


def google_init(oauth: OAuth, app: Flask) -> None:
	"""
	Initialize Google OAuth.

	:param oauth: The OAuth object.
	:param app: The Flask app.
	:return: None
	"""
	oauth.register(
		name='google',
		client_id=app.config['GOOGLE_CLIENT_ID'],
		client_secret=app.config['GOOGLE_CLIENT_SECRET'],
		server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
		client_kwargs={
			'scope': 'openid email profile'
    	}
	)


def github_init(oauth: OAuth, app: Flask) -> None:
	"""
	Initialize GitHub OAuth.

	:param oauth: The OAuth object.
	:param app: The Flask app.
	:return: None
	"""
	oauth.register(
		name='github',
		client_id=app.config['GITHUB_CLIENT_ID'],
		client_secret=app.config['GITHUB_CLIENT_SECRET'],
		access_token_url='https://github.com/login/oauth/access_token',
		access_token_params=None,
		authorize_url='https://github.com/login/oauth/authorize',
		authorize_params=None,
		api_base_url='https://api.github.com/',
		client_kwargs={
			'scope': 'user:email'
		}
	)


__all__ = ['db', 'mail', 'oauth', 'session', 'migrate', 'google_init', 'github_init']


if __name__ == '__main__':
	pass
