# INFO: Helper functions for the app
from validator_collection import validators, errors
from flask import flash, redirect, url_for, session
from functools import wraps
from app.models import User
from zxcvbn import zxcvbn


def validate_username(username: str) -> str | None:
	username = username.strip().lower()
	if not username:
		return 'Username is required'
	if not username.isalnum():
		return 'Username must be alphanumeric'
	if len(username) < 3 or len(username) > 100:
		return 'Username must be between 3 and 100 characters'
	if User.query.filter_by(username=username).first():
		return 'Username is already taken'
	return None


def validate_email(email: str) -> str | None:
	try:
		email = validators.email(email).strip()
	except errors.EmptyValueError:
		return 'Email is required'
	except errors.InvalidEmailError:
		return 'Email is invalid'
	if len(email) > 100:
		return 'We do not accept emails longer than 100 characters'
	if User.query.filter_by(email=email).first():
		return 'Email is already taken'
	return None


def validate_password(password: str, confirmation: str) -> str | None:
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


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function
