from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app as app
from app.models import User
from app.extensions import db, oauth
from app.helpers import session_add
from werkzeug.security import check_password_hash


login = Blueprint('login', __name__)


@login.route('/', methods=['GET'])
def index() -> str:
	"""
	This function renders the login page.

	:return: The login template.
	"""
	return render_template('login/index.html')


@login.route('/email', methods=['POST'])
def login_email() -> str:
	"""
	This function handles the login by email route.

	:return: Redirect to the main page if successful login, otherwise redirect back to the login page.
	"""
	session.clear()

	email = request.form['email'].strip()
	if not email:
		flash('Email is required', 'warning')
		return redirect(url_for('login.index'))

	user = User.query.filter_by(email=email).first()

	password = request.form['password']
	if not password:
		flash('Password is required', 'warning')
		return redirect(url_for('login.index'))

	if user is None or not check_password_hash(user.password, password):
		flash('Invalid credentials', 'warning')
		return redirect(url_for('login.index'))

	session_add(user)

	flash('Logged in successfully', 'success')
	return redirect(url_for('home.index'))


@login.route('/google', methods=['GET'])
def login_google() -> str:
	"""
	This function handles the login with Google route.

	:return: Redirect to the Google login page.
	"""
	try:
		redirect_uri = url_for('login.authorize_google', _external=True)
		return oauth.google.authorize_redirect(redirect_uri)

	except Exception as e:
		flash('An error occurred during login with Google', 'danger')
		app.logger.error(e)
		return redirect(url_for('login.index'))


@login.route('/google/authorize', methods=['GET'])
def authorize_google() -> str:
	"""
	This function authorizes the user with Google+ API.

	:return: Redirect to the main page if successful login, otherwise redirect back to the login page.
	"""
	try:
		oauth.google.authorize_access_token()
		userinfo_endpoint = oauth.google.server_metadata['userinfo_endpoint']
		response = oauth.google.get(userinfo_endpoint)
		userinfo = response.json()

		email = userinfo['email']
		oauth_id = userinfo['sub']
		oauth_provider = 'google'

		user = User.query.filter_by(email=email).first()
		updated = False

		if not user:
			user = User(
				email=email,
				password=None,
				oauth_provider=oauth_provider,
				oauth_id=oauth_id
			)
			db.session.add(user)
			updated = True

		elif user.oauth_provider != oauth_provider or user.oauth_id != oauth_id:
			user.oauth_provider = oauth_provider
			user.oauth_id = oauth_id
			updated = True

		if updated:
			db.session.commit()

		session_add(user, oauth_provider, oauth_id)

		flash('Logged in successfully', 'success')
		return redirect(url_for('home.index'))

	except Exception as e:
		flash('Error occurred during authorization with Google', 'danger')
		app.logger.error(e)
		return redirect(url_for('login.index'))


@login.route('/github', methods=['GET'])
def login_github() -> str:
	"""
	This function handles the login with GitHub route.

	:return: Redirect to the GitHub login page.
	"""
	try:
		redirect_uri = url_for('login.authorize_github', _external=True)
		return oauth.github.authorize_redirect(redirect_uri)

	except Exception as e:
		flash('Error occurred during login with GitHub', 'danger')
		app.logger.error(e)
		return redirect(url_for('login.index'))


@login.route('/github/authorize', methods=['GET'])
def authorize_github() -> str:
	"""
	This function authorizes the user with GitHub API.

	:return: Redirect to the main page if successful login, otherwise redirect back to the login page.
	"""
	try:
		oauth.github.authorize_access_token()
		response = oauth.github.get('user').json()
		email = response['email']
		oauth_id = response['id']
		oauth_provider = 'github'

		user = User.query.filter_by(email=email).first()
		updated = False

		if not user:
			user = User(
				email=email,
				password=None,
				oauth_provider=oauth_provider,
				oauth_id=oauth_id
			)
			db.session.add(user)
			updated = True

		elif user.oauth_provider != oauth_provider or user.oauth_id != oauth_id:
			user.oauth_provider = oauth_provider
			user.oauth_id = oauth_id
			updated = True

		if updated:
			db.session.commit()

		session_add(user, oauth_provider, oauth_id)

		flash('Logged in successfully', 'success')
		return redirect(url_for('home.index'))

	except Exception as e:
		flash('Error occurred during authorization with GitHub', 'danger')
		app.logger.error(e)
		return redirect(url_for('login.index'))


if __name__ == '__main__':
	pass
