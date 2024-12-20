# INFO: Initialize the Flask app and set up logging

from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_session import Session
import logging

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

Session(app)

def username(user_id: int) -> str:
	from app.models import User
	user = User.query.get(user_id)
	return user.username
app.jinja_env.filters['username'] = username

from app import routes, models

# Set up console logging
if not app.debug:
	stream_handler = logging.StreamHandler()
	stream_handler.setLevel(logging.INFO)
	app.logger.addHandler(stream_handler)

app.logger.setLevel(logging.INFO)
app.logger.info('Flask App startup')
