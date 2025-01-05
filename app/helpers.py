import os
from zxcvbn import zxcvbn
from functools import wraps
from app.models import User
from dotenv import load_dotenv
from flask_mail import Message
from validator_collection import validators, errors
from flask import flash, redirect, url_for, session, render_template


load_dotenv()


def validate_username(username: str) -> str | None:
	"""
	Validate username input and return an error message if invalid, otherwise return None.

	:param username: The username to validate.
	:return: An error message if the username is invalid, otherwise None.
	"""
	username = username.strip().lower()
	if not username:
		return 'Username is required'
	if not username.isalnum():
		return 'Username must be alphanumeric'
	if len(username) < 3:
		return 'Username must be at least 3 characters'
	if len(username) > 100:
		return 'Username is too long'
	if User.query.filter_by(username=username).first():
		return 'Username is already taken'
	return None


def validate_email(email: str) -> str | None:
	"""
	Validate email input and return an error message if invalid, otherwise return None.

	:param email: The email to validate.
	:return: An error message if the email is invalid, otherwise None.
	"""
	email = email.strip()
	if not email:
		return 'Email is required'
	try:
		validators.email(email)
	except errors.InvalidEmailError:
		return 'Email is invalid'
	if len(email) > 100:
		return 'Email is too long'
	if User.query.filter_by(email=email).first():
		return 'Email is already taken'
	return None


def validate_password(password: str, confirmation: str) -> str | None:
	"""
	Validate password input and return an error message if invalid, otherwise return None.

	:param password: The password to validate.
	:param confirmation: The password confirmation to validate.
	:return: An error message if the password is invalid, otherwise None.
	"""
	if not password:
		return 'Password is required'
	if not confirmation:
		return 'Confirmation is required'
	if len(password) < 8:
		return 'Password must be at least 8 characters'
	if zxcvbn(password)['score'] < 3:
		return 'Password is too weak'
	if password != confirmation:
		return 'Password and confirmation do not match'
	return None


def create_reset_password_email(user: User) -> Message:
	"""
	Create a reset password email for the user.

	:param user: The user to create the email for.
	:return: The reset password email.
	"""
	token = user.get_token()
	msg = Message(
		subject='[Pomodoro 50] Reset Password Request',
		sender=os.getenv('MAIL_USERNAME'),
		recipients=[user.email]
	)
	reset_url = url_for('main.reset_password_token', token=token, _external=True)
	msg.body = render_template('emails/reset_password_email.txt', username=user.username, reset_url=reset_url)
	msg.html = render_template('emails/reset_password_email.html', username=user.username, reset_url=reset_url)
	return msg


def session_add(user: User, oauth_provider: str = None, oauth_id: str = None) -> None:
	"""
	Add a user to the session

	:param user: The user object.
	:param oauth_provider: The OAuth provider.
	:param oauth_id: The OAuth ID.
	:return: None
	"""
	session['user_id'] = user.id
	session['username'] = user.username
	session['email'] = user.email
	session['oauth_provider'] = oauth_provider if oauth_provider is not None else user.oauth_provider
	if oauth_id:
		session['oauth_id'] = oauth_id


def login_required(f) -> callable:
    """
    Decorate routes to require login.

	:param f: The function to decorate.
	:return: The decorated function.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs) -> callable:
        if session.get("user_id") is None:
            flash('Please login to access this page', 'warning')
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


def profile_completed_required(f) -> callable:
	"""
	Decorate routes to require a completed profile.

	:param f: The function to decorate.
	:return: The decorated function.
	"""
	@wraps(f)
	def decorated_function(*args, **kwargs) -> callable:
		user = User.query.get(session['user_id'])
		if user and (user.username is None or user.email is None or user.password is None):
			flash('Please complete your profile before proceeding', 'warning')
			return redirect(url_for('main.profile_complete'))
		return f(*args, **kwargs)

	return decorated_function


if __name__ == '__main__':
	pass
