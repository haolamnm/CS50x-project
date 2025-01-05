from app import create_app
from app.extensions import db
from app.models import User
from app.helpers import validate_username, validate_email, validate_password
from unittest import TestCase, main
from pytest import mark
from app.config import TestConfig
from werkzeug.security import generate_password_hash
from tests.cases import *


pytestmark = mark.filterwarnings('ignore::DeprecationWarning')


class TestHelpers(TestCase):
	def setUp(self) -> None:
		self.app = create_app(TestConfig)
		self.app_context = self.app.app_context()
		self.app_context.push()
		self.client = self.app.test_client()
		db.create_all()

		self.test_username = TEST_USERNAME
		self.test_password = TEST_PASSWORD
		self.test_email = TEST_EMAIL

		self.test_user = User(
			username=self.test_username,
			email=self.test_email,
			password=generate_password_hash(self.test_password, salt_length=16)
		)
		db.session.add(self.test_user)
		db.session.commit()


	def tearDown(self) -> None:
		db.session.remove()
		db.drop_all()
		self.app_context.pop()


	def test_validate_username(self) -> None:
		for username, error in INVALID_USERNAME_TEST_CASES:
			self.assertEqual(validate_username(username), error)
		self.assertEqual(validate_username(r'valid'), None)


	def test_validate_email(self) -> None:
		for email, error in INVALID_EMAIL_TEST_CASES:
			self.assertEqual(validate_email(email), error)
		self.assertEqual(validate_email(r'valid@gmail.com'), None)


	def test_validate_password(self) -> None:
		for password, confirmation, error in INVALID_PASSWORD_TEST_CASES:
			self.assertEqual(validate_password(password, confirmation), error)
		self.assertEqual(validate_password(TEST_PASSWORD, TEST_PASSWORD), None)


if __name__ == '__main__':
	main()
