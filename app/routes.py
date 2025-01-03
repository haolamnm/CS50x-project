from flask import current_app as app, render_template, flash, redirect, url_for, request, session, Blueprint
from app.helpers import validate_username, validate_email, validate_password, login_required, profile_completed_required
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User
from app import db
from flask_mail import Mail, Message # type: ignore
from authlib.integrations.flask_client import OAuth # type: ignore
import uuid


main = Blueprint('main', __name__)


oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

github = oauth.register(
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

mail = Mail(app)


@main.after_request
def after_request(response: object) -> object:
	""""Ensure responses aren't cached"""
	response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
	response.headers['Expires'] = 0
	response.headers['Pragma'] = 'no-cache'
	return response


@main.route('/', methods=['GET'])
def index() -> str:
	return render_template('index.html')


@main.route('/register', methods=['GET', 'POST'])
def register() -> str:
	if request.method == 'POST':
		username = request.form['username'].strip().lower()
		username_error = validate_username(username)
		if username_error:
			flash(username_error, 'warning')
			return redirect(url_for('main.register'))

		email = request.form['email'].strip()
		email_error = validate_email(email)
		if email_error:
			flash(email_error, 'warning')
			return redirect(url_for('main.register'))

		password = request.form['password']
		confirmation = request.form['confirmation']
		password_error = validate_password(password, confirmation)
		if password_error:
			flash(password_error, 'warning')
			return redirect(url_for('main.register'))

		user = User(
			username=username,
			email=email,
			password=generate_password_hash(password, salt_length=16)
		)
		db.session.add(user)
		db.session.commit()

		session['user_id'] = user.id
		session['username'] = user.username
		session['email'] = user.email
		session['oauth_provider'] = user.oauth_provider

		flash('User registered successfully', 'success')
		return redirect(url_for('main.index'))
	else:
		return render_template('register.html')


@main.route('/login', methods=['GET', 'POST'])
def login() -> str:
	if request.method == 'POST':
		session.clear()
		login_type = request.form['login_type']
		if login_type not in ['username_login', 'email_login']:
			flash('Invalid login type', 'warning')
			return redirect(url_for('main.login'))

		user = None

		if login_type == 'username_login':
			username = request.form['username'].strip().lower()
			if not username:
				flash('Username is required', 'warning')
				return redirect(url_for('main.login'))
			user = User.query.filter_by(username=username).first()

		elif login_type == 'email_login':
			email = request.form['email'].strip()
			if not email:
				flash('Email is required', 'warning')
				return redirect(url_for('main.login'))
			user = User.query.filter_by(email=email).first()

		password = request.form['password']
		if not password:
			flash('Password is required', 'warning')
			return redirect(url_for('main.login'))

		if user is None or not check_password_hash(user.password, password):
			flash('Invalid credentials', 'warning')
			return redirect(url_for('main.login'))

		session['user_id'] = user.id
		session['username'] = user.username
		session['email'] = user.email
		session['oauth_provider'] = user.oauth_provider

		flash('Logged in successfully', 'success')
		return redirect(url_for('main.index'))
	else:
		return render_template('login.html')


@main.route('/logout', methods=['GET'])
@login_required
@profile_completed_required
def logout() -> str:
	session.clear()
	flash('Logged out successfully', 'success')
	return redirect(url_for('main.index'))


@main.route('/profile', methods=['GET'])
@login_required
@profile_completed_required
def profile() -> str:
	user = User.query.get(session['user_id'])
	return render_template('profile.html', user=user)


@main.route('/timer', methods=['GET'])
@login_required
@profile_completed_required
def timer() -> str:
	return render_template('timer.html')


@main.route('/update', methods=['POST'])
@login_required
@profile_completed_required
def update() -> str:
	update_type = request.form['update_type']
	if update_type not in ['username_update', 'email_update', 'password_update']:
		flash('Invalid update type', 'warning')
		return redirect(url_for('main.profile'))

	password = request.form['password']
	if not password:
		flash('Password is required', 'warning')
		return redirect(url_for('main.profile'))

	user = User.query.get(session['user_id'])

	if not check_password_hash(user.password, password):
		flash('Invalid credentials', 'warning')
		return redirect(url_for('main.profile'))

	if update_type == 'username_update':
		new_username = request.form['new_username'].strip().lower()
		new_username_error = validate_username(new_username)
		if new_username_error:
			flash(new_username_error, 'warning')
			return redirect(url_for('main.profile'))
		user.username = new_username

	elif update_type == 'email_update':
		new_email = request.form['new_email'].strip()
		new_email_error = validate_email(new_email)
		if new_email_error:
			flash(new_email_error, 'warning')
			return redirect(url_for('main.profile'))
		user.email = new_email

	elif update_type == 'password_update':
		new_password = request.form['new_password']
		new_confirmation = request.form['new_confirmation']
		new_password_error = validate_password(new_password, new_confirmation)
		if new_password_error:
			flash(new_password_error, 'warning')
			return redirect(url_for('main.profile'))
		user.password = generate_password_hash(new_password, salt_length=16)

	try:
		db.session.commit()
		session['username'] = user.username
		session['email'] = user.email
		flash('Profile updated successfully', 'success')
	except Exception as e:
		db.session.rollback()
		flash('An error occurred', 'danger')
		app.logger.error(e)

	return redirect(url_for('main.profile'))


@main.route('/login/google', methods=['GET'])
def login_google() -> str:
	try:
		redirect_uri = url_for('main.authorize_google', _external=True)
		return google.authorize_redirect(redirect_uri)
	except Exception as e:
		flash('An error occurred during login with Google', 'danger')
		app.logger.error(e)
		return redirect(url_for('main.login'))


@main.route('/login/google/authorize', methods=['GET'])
def authorize_google() -> str:
	try:
		token = google.authorize_access_token()
		userinfo_endpoint = google.server_metadata['userinfo_endpoint']
		response = google.get(userinfo_endpoint)
		userinfo = response.json()

		email = userinfo['email']
		oauth_id = userinfo['sub']
		oauth_provider = 'google'

		user = User.query.filter_by(email=email).first()
		updated = False

		if not user:
			username = userinfo['email'].split('@')[0]
			username_error = validate_username(username)
			if username_error:
				username = 'user_' + str(uuid.uuid4().hex[:8])
			user = User(
				username=None,
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

		session['user_id'] = user.id
		session['username'] = user.username
		session['email'] = user.email
		session['oauth_provider'] = oauth_provider
		session['oauth_id'] = oauth_id

		flash('Logged in successfully', 'success')
		return redirect(url_for('main.index'))

	except Exception as e:
		flash('Error occurred during authorization with Google', 'danger')
		app.logger.error(e)
		return redirect(url_for('main.login'))


@main.route('/login/github', methods=['GET'])
def login_github() -> str:
	try:
		redirect_uri = url_for('main.authorize_github', _external=True)
		return github.authorize_redirect(redirect_uri)
	except Exception as e:
		flash('Error occurred during login with GitHub', 'danger')
		app.logger.error(e)
		return redirect(url_for('main.login'))


@main.route('/login/github/authorize', methods=['GET'])
def authorize_github() -> str:
	try:
		token = github.authorize_access_token()
		response = github.get('user').json()
		email = response['email']
		username = response['login']
		oauth_id = response['id']
		oauth_provider = 'github'

		user = User.query.filter_by(email=email).first()
		updated = False

		if not user:
			user = User(
				username=username,
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

		session['user_id'] = user.id
		session['username'] = user.username
		session['email'] = user.email
		session['oauth_provider'] = oauth_provider
		session['oauth_id'] = oauth_id

		flash('Logged in successfully', 'success')
		return redirect(url_for('main.index'))

	except Exception as e:
		flash('Error occurred during authorization with GitHub', 'danger')
		app.logger.error(e)
		return redirect(url_for('main.login'))


@main.route('/profile/complete', methods=['GET', 'POST'])
@login_required
def profile_complete() -> str:
	user = User.query.get(session['user_id'])

	if user.username is not None and user.email is not None and user.password is not None:
		flash('Profile is already complete', 'info')
		return redirect(url_for('main.profile'))

	elif request.method == 'POST':
		if user.username is None or user.username == '':
			username = request.form['username'].strip().lower()
			username_error = validate_username(username)
			if username_error:
				flash(username_error, 'warning')
				return redirect(url_for('main.profile_complete'))

			user.username = username

		if user.email is None or user.email == '':
			email = request.form['email'].strip()
			email_error = validate_email(email)
			if email_error:
				flash(email_error, 'warning')
				return redirect(url_for('main.profile_complete'))

			user.email = email

		if user.password is None or user.password == '':
			password = request.form['password']
			confirmation = request.form['confirmation']
			password_error = validate_password(password, confirmation)
			if password_error:
				flash(password_error, 'warning')
				return redirect(url_for('main.profile_complete'))

			user.password = generate_password_hash(password, salt_length=16)

		db.session.commit()

		session['username'] = user.username
		session['email'] = user.email
		session['oauth_provider'] = user.oauth_provider

		flash('Profile completed successfully', 'success')
		return redirect(url_for('main.profile'))

	else:
		return render_template('profile_complete.html', user=user)


def send_reset_email(user: User) -> None:
	token = user.get_token()
	msg = Message(
		subject='[Pomodoro 50] Reset Password Request',
		sender=app.config['MAIL_USERNAME'],
		recipients=[user.email]
	)
	reset_url = url_for('main.reset_password_token', token=token, _external=True)
	msg.body = render_template('emails/reset_password_email.txt', username=user.username, reset_url=reset_url)
	msg.html = render_template('emails/reset_password_email.html', username=user.username, reset_url=reset_url)
	mail.send(msg)


@main.route('/reset_password', methods=['GET', 'POST'])
def reset_password() -> str:
	if request.method == 'POST':
		email = request.form['email'].strip()

		user = User.query.filter_by(email=email).first()
		if not user:
			flash('User not found', 'warning')
			return redirect(url_for('main.reset_password'))
		else:
			send_reset_email(user)
			flash('Reset email sent', 'success')
			return redirect(url_for('main.login'))

	else:
		return render_template('reset_password.html')


@main.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token: str) -> None:
	user = User.verify_token(token)
	if user is None:
		flash('Invalid or expired token', 'warning')
		return redirect(url_for('main.reset_password'))

	if request.method == 'POST':
		new_password = request.form['new_password']
		confirmation = request.form['confirmation']

		password_error = validate_password(new_password, confirmation)
		if password_error:
			flash(password_error, 'warning')
			return redirect(url_for('main.reset_password_token', token=token))

		user.password = generate_password_hash(new_password, salt_length=16)
		db.session.commit()

		flash('Password changed successfully', 'success')
		return redirect(url_for('main.login'))

	else:
		return render_template('change_password.html', token=token)

