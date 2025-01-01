from flask import current_app as app, render_template, flash, redirect, url_for, request, session, Blueprint
from app.helpers import validate_username, validate_email, validate_password, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User
from app import db


main = Blueprint('main', __name__)


@main.after_request
def after_request(response):
	""""Ensure responses aren't cached"""
	response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
	response.headers['Expires'] = 0
	response.headers['Pragma'] = 'no-cache'
	return response


@main.route('/')
def index():
	return render_template('index.html')


@main.route('/register', methods=['GET', 'POST'])
def register():
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
		flash('User registered successfully', 'success')
		return redirect(url_for('main.index'))
	else:
		return render_template('register.html')


@main.route('/login', methods=['GET', 'POST'])
def login():
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
		flash('Logged in successfully', 'success')
		return redirect(url_for('main.index'))
	else:
		return render_template('login.html')


@main.route('/logout')
@login_required
def logout():
	session.pop('user_id', None)
	session.pop('username', None)
	session.pop('email', None)
	flash('Logged out successfully', 'success')
	return redirect(url_for('main.index'))


@main.route('/profile')
@login_required
def profile():
	user = User.query.get(session['user_id'])
	return render_template('profile.html', user=user)


@main.route('/timer')
@login_required
def timer():
	return render_template('timer.html')


@main.route('/update', methods=['POST'])
@login_required
def update():
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
		print(e)

	return redirect(url_for('main.profile'))
