import unittest
import pytest # type: ignore
from app import create_app, db
from app.models import User
from config import TestConfig
from werkzeug.security import generate_password_hash
from app.helpers import validate_username, validate_email, validate_password
from tests.cases import TEST_USERNAME, TEST_PASSWORD, TEST_EMAIL, INVALID_USERNAME_TEST_CASES, INVALID_EMAIL_TEST_CASES, INVALID_PASSWORD_TEST_CASES


pytestmark = pytest.mark.filterwarnings('ignore::DeprecationWarning')


class TestHelpers(unittest.TestCase):
	def setUp(self):
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


	def tearDown(self):
		db.session.remove()
		db.drop_all()
		self.app_context.pop()


	def test_validate_username(self):
		for username, error in INVALID_USERNAME_TEST_CASES:
			self.assertEqual(validate_username(username), error)
		self.assertEqual(validate_username(r'valid'), None)


	def test_validate_email(self):
		for email, error in INVALID_EMAIL_TEST_CASES:
			self.assertEqual(validate_email(email), error)
		self.assertEqual(validate_email(r'valid@gmail.com'), None)


	def test_validate_password(self):
		for password, confirmation, error in INVALID_PASSWORD_TEST_CASES:
			self.assertEqual(validate_password(password, confirmation), error)
		self.assertEqual(validate_password(TEST_PASSWORD, TEST_PASSWORD), None)


if __name__ == '__main__':
	unittest.main()
