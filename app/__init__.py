import logging
from flask import Flask, render_template, flash
from app.config import Config
from app.extensions import *
from app.routes import *


def create_app(config_class: type[Config] = Config) -> Flask:
	"""
	Create and configure the Flask app.

	:param config_class: The configuration class to use.
	:return: The Flask app instance.
	"""
	app = Flask(__name__, template_folder='templates', static_folder='static')
	app.config.from_object(config_class)

	# INFO: Initialize extensions
	db.init_app(app)
	mail.init_app(app)
	session.init_app(app)
	migrate.init_app(app, db)
	oauth.init_app(app)
	google_init(oauth, app)
	github_init(oauth, app)
	app.logger.info('[INFO] Extensions initialized')

	# INFO: Create the database
	with app.app_context():
		db.create_all()
		app.logger.info('[INFO] Database created')

	# INFO: Set up console logging
	if not app.debug and not app.testing:
		stream_handler = logging.StreamHandler()
		stream_handler.setLevel(logging.INFO)
		app.logger.addHandler(stream_handler)

	app.logger.setLevel(logging.INFO)
	app.logger.info('[INFO] Flask app successfully started')

	# INFO: Register the blueprints
	app.register_blueprint(main)
	app.register_blueprint(home, url_prefix='/')
	app.register_blueprint(timer, url_prefix='/timer')
	app.register_blueprint(about, url_prefix='/about')
	app.register_blueprint(login, url_prefix='/login')
	app.register_blueprint(signup, url_prefix='/signup')
	app.register_blueprint(logout, url_prefix='/logout')
	app.register_blueprint(profile, url_prefix='/profile')
	app.register_blueprint(history, url_prefix='/history')
	app.register_blueprint(insights, url_prefix='/insights')
	app.register_blueprint(settings, url_prefix='/settings')

	# INFO: Register the error handlers
	@app.errorhandler(404)
	def page_not_found(e):
		flash('Page not found', 'danger')
		return render_template('errors/404.html'), 404

	return app


if __name__ == '__main__':
	pass
