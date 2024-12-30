import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_session import Session
from config import Config


db = SQLAlchemy()
migrate = Migrate()


def create_app(config_class=Config):
	app = Flask(__name__)
	app.config.from_object(config_class)

	db.init_app(app)
	migrate.init_app(app, db)
	Session(app)

	with app.app_context():
		from app import routes, models
		db.create_all()

	# Set up console logging
	if not app.debug:
		stream_handler = logging.StreamHandler()
		stream_handler.setLevel(logging.INFO)
		app.logger.addHandler(stream_handler)

	app.logger.setLevel(logging.INFO)
	app.logger.info('Flask App startup')

	return app
