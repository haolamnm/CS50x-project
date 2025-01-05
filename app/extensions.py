from flask_mail import Mail
from flask_migrate import Migrate
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth


db = SQLAlchemy()
mail = Mail()
oauth = OAuth()
session = Session()
migrate = Migrate()


if __name__ == '__main__':
	pass
