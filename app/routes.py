from flask import render_template, flash, redirect, url_for, request
from app.helpers import validate_username, validate_email, validate_password
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User
from app import app, db


@app.after_request
def after_request(response):
	""""Ensure responses aren't cached"""
	response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
	response.headers['Expires'] = 0
	response.headers['Pragma'] = 'no-cache'
	return response


@app.route('/')
def index():
	"""TODO: write description"""
	return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
	if request.method == 'POST':
		username = request.form['username'].strip().lower()
		username_error = validate_username(username)
		if username_error:
			flash(username_error)
			return redirect(url_for('register'))

		email = request.form['email'].strip()
		email_error = validate_email(email)
		if email_error:
			flash(email_error)
			return redirect(url_for('register'))

		password = request.form['password']
		confirmation = request.form['confirmation']
		password_error = validate_password(password, confirmation)
		if password_error:
			flash(password_error)
			return redirect(url_for('register'))

		user = User(
			username=username,
			email=email,
			password=generate_password_hash(password, salt_length=16)
		)
		db.session.add(user)
		db.session.commit()
		flash('User registered successfully', 'success')
		return redirect(url_for('index'))
	else:
		return render_template('register.html')
