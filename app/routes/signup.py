from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.models import User
from app.extensions import db
from app.helpers import validate_email, validate_password, session_add
from werkzeug.security import generate_password_hash


signup = Blueprint('signup', __name__)


@signup.route('/', methods=['GET'])
def index() -> str:
	"""
	This function renders the registration page.

	:return: The registration template.
	"""
	return render_template('signup/index.html')


@signup.route('/email', methods=['POST'])
def signup_email() -> str:
	"""
	This function handles the registration by email route.

	:return: Redirect to the main page if successful registration, otherwise redirect back to the registration page.
	"""
	email = request.form['email'].strip()
	email_error = validate_email(email)
	if email_error:
		flash(email_error, 'warning')
		return redirect(url_for('signup.index'))

	password = request.form['password']
	confirmation = request.form['confirmation']
	password_error = validate_password(password, confirmation)
	if password_error:
		flash(password_error, 'warning')
		return redirect(url_for('signup.index'))

	user = User(
		email=email,
		password=generate_password_hash(password, salt_length=16)
	)
	db.session.add(user)
	db.session.commit()

	session_add(user)

	flash('User registered successfully', 'success')
	return redirect(url_for('home.index'))


if __name__ == '__main__':
	pass
