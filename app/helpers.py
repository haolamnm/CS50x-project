# INFO: Helper functions for the app
from validator_collection import validators, errors
from zxcvbn import zxcvbn


def validate_username(username: str) -> str | None:
    username = username.strip().lower()
    if not username:
        return 'Username is required'
    if not username.isalnum():
        return 'Username must be alphanumeric'
    if len(username) < 3 or len(username) > 100:
        return 'Username must be between 3 and 100 characters'
    if " " in username or "\t" in username or "\n" in username:
        return 'Username must be a single word'
    return None


def validate_email(email: str) -> str | None:
	try:
		email = validators.email(email).strip()
	except errors.EmptyValueError:
		return 'Email is required'
	except errors.InvalidEmailError:
		return 'Email is invalid'
	return None


def validate_password(password: str, confirmation: str) -> str | None:
	if not password:
		return 'Password is required'
	if len(password) < 8:
		return 'Password must be at least 8 characters'
	if zxcvbn(password)['score'] < 3:
		return 'Password is too weak'
	if not confirmation:
		return 'Confirmation is required'
	if password != confirmation:
		return 'Password and confirmation do not match'
	return None
