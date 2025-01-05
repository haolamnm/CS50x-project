import logging
from flask import Flask
from app.config import Config
from app.extensions import *


def create_app(config_class: type[Config] = Config) -> Flask:
	"""
	Create and configure the Flask app.

	:param config_class: The configuration class to use.
	:return: The Flask app instance.
	"""
	app = Flask(__name__)
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
		from app import routes, models, helpers
		db.create_all()
		app.logger.info('[INFO] Database created')

	# INFO: Set up console logging
	if not app.debug and not app.testing:
		stream_handler = logging.StreamHandler()
		stream_handler.setLevel(logging.INFO)
		app.logger.addHandler(stream_handler)

	app.logger.setLevel(logging.INFO)
	app.logger.info('[INFO] Flask app successfully started')

	# INFO: Register the main blueprint
	from app.routes import main as main_blueprint
	app.register_blueprint(main_blueprint)

	return app


if __name__ == '__main__':
	pass
