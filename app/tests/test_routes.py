import unittest
from app import app, db
from app.models import User
from config import TestConfig
from flask import url_for
from werkzeug.security import generate_password_hash


class TestRoutes(unittest.TestCase):
	def setUp(self):
		pass
