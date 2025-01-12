from flask import Blueprint, session, redirect, url_for, flash
from app.helpers import login_required, profile_completed_required


logout = Blueprint('logout', __name__)


@logout.route('/', methods=['GET'])
@login_required
def index() -> str:
	"""
	This function will log the user out and clear the session.

	:return: Redirect to the homepage.
	"""
	session.clear()
	flash('Logged out successfully', 'success')
	return redirect(url_for('home.index'))


if __name__ == '__main__':
	pass
