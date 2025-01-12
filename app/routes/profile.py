from flask import render_template, session, Blueprint, request, flash, redirect, url_for, current_app as app
from app.models import User
from app.helpers import login_required, profile_completed_required, validate_email, validate_password, session_add, create_reset_password_email
from app.extensions import db, mail
from werkzeug.security import generate_password_hash, check_password_hash


profile = Blueprint('profile', __name__)


@profile.route('/', methods=['GET'])
@login_required
@profile_completed_required
def index() -> str:
	"""
	This function renders the profile page.

	:return: Render the profile template.
	"""
	user = User.query.get(session['user_id'])
	return render_template('profile/index.html', user=user)


@profile.route('/update/email', methods=['POST'])
@login_required
@profile_completed_required
def update_email() -> str:
	"""
	This function updates the user's email.

	:return: Redirect to the profile page.
	"""
	password = request.form['password']
	if not password:
		flash('Password is required', 'warning')
		return redirect(url_for('profile.index'))

	user = User.query.get(session['user_id'])

	if not check_password_hash(user.password, password):
		flash('Invalid credentials', 'warning')
		return redirect(url_for('profile.index'))

	new_email = request.form['new_email'].strip()
	new_email_error = validate_email(new_email)
	if new_email_error:
		flash(new_email_error, 'warning')
		return redirect(url_for('profile.index'))
	user.email = new_email

	try:
		db.session.commit()
		session_add(user, user.oauth_provider)
		flash('Profile updated successfully', 'success')

	except Exception as e:
		db.session.rollback()
		flash('An error occurred', 'danger')
		app.logger.error(e)

	return redirect(url_for('profile.index'))


@profile.route('/update/password', methods=['POST'])
@login_required
@profile_completed_required
def update_password() -> str:
	"""
	This function updates the user's password.

	:return: Redirect to the profile page.
	"""
	password = request.form['password']
	if not password:
		flash('Password is required', 'warning')
		return redirect(url_for('profile.index'))

	user = User.query.get(session['user_id'])

	if not check_password_hash(user.password, password):
		flash('Invalid credentials', 'warning')
		return redirect(url_for('profile.index'))

	new_password = request.form['new_password']
	new_confirmation = request.form['new_confirmation']
	new_password_error = validate_password(new_password, new_confirmation)
	if new_password_error:
		flash(new_password_error, 'warning')
		return redirect(url_for('profile.index'))
	user.password = generate_password_hash(new_password, salt_length=16)

	try:
		db.session.commit()
		session_add(user)
		flash('Profile updated successfully', 'success')

	except Exception as e:
		db.session.rollback()
		flash('An error occurred', 'danger')
		app.logger.error(e)

	return redirect(url_for('profile.index'))


@profile.route('/complete/password', methods=['GET', 'POST'])
@login_required
def complete_password() -> str:
	"""
	This function completes the user's password.

	:return: Redirect to the profile page.
	"""
	if request.method == 'POST':
		user = User.query.get(session['user_id'])

		if user.password is not None:
			flash('Profile is already complete', 'info')
			return redirect(url_for('profile.index'))

		else:
			password = request.form['password']
			confirmation = request.form['confirmation']
			password_error = validate_password(password, confirmation)
			if password_error:
				flash(password_error, 'warning')
				return redirect(url_for('profile.complete_password'))

			user.password = generate_password_hash(password, salt_length=16)
			db.session.commit()
			session_add(user, user.oauth_provider)

			flash('Profile completed successfully', 'success')
			return redirect(url_for('profile.index'))

	return render_template('profile/complete_password.html')


@profile.route('/reset/password', methods=['GET', 'POST'])
def reset_password() -> str:
	"""
	This function resets the user's password by sending an email with a reset link.

	:return: Redirect to the profile page.
	"""
	if request.method == 'POST':
		email = request.form['email'].strip()
		user = User.query.filter_by(email=email).first()

		if not user:
			flash('User not found', 'warning')
			return redirect(url_for('profile.reset_password'))
		else:
			msg = create_reset_password_email(user)
			app.logger.info(f'[INFO] Mail object: {mail}')
			mail.send(msg)
			flash('Reset email sent', 'success')
			return redirect(url_for('login.index'))

	return render_template('profile/reset_password.html')


@profile.route('/reset/password/<token>', methods=['GET', 'POST'])
def reset_password_token(token: str) -> str:
	"""
	This function resets the user's password using a token sent by email.

	:param token: The token.
	:return: The new password reset template.
	"""
	user = User.verify_token(token)
	if user is None:
		flash('Invalid or expired token', 'warning')
		return redirect(url_for('profile.reset_password'))

	if request.method == 'POST':
		new_password = request.form['new_password']
		confirmation = request.form['confirmation']

		password_error = validate_password(new_password, confirmation)
		if password_error:
			flash(password_error, 'warning')
			return redirect(url_for('profile.reset_password_token', token=token))

		user.password = generate_password_hash(new_password, salt_length=16)
		db.session.commit()

		flash('Password changed successfully', 'success')
		return redirect(url_for('login.index'))

	return render_template('profile/reset_password_token.html', token=token)


@profile.route('/delete', methods=['POST'])
@login_required
def delete() -> str:
	"""
	This function deletes the user's account.

	:return: Redirect to the homepage.
	"""
	password = request.form['password']
	if not password:
		flash('Password is required', 'warning')
		return redirect(url_for('profile.index'))

	user = User.query.get(session['user_id'])

	if not check_password_hash(user.password, password):
		flash('Invalid credentials', 'warning')
		return redirect(url_for('profile.index'))

	try:
		db.session.delete(user)
		db.session.commit()
		session.clear()
		flash('Account deleted successfully', 'success')

	except Exception as e:
		db.session.rollback()
		flash('An error occurred', 'danger')
		app.logger.error(e)
		return redirect(url_for('profile.index'))

	return redirect(url_for('signup.index'))


if __name__ == '__main__':
	pass
