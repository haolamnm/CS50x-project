import os
import sys
import unittest
from app import create_app, db
from app.models import User
from config import TestConfig
from tests import CustomTextTestRunner
from werkzeug.security import generate_password_hash
from app.helpers import validate_username, validate_email, validate_password


TEST_USERNAME = r'username'
TEST_PASSWORD = r'TwFY412nXInZ41nn'
TEST_EMAIL = r'test@gmail.com'


class TestHelpers(unittest.TestCase):
	def __init__(self, *args, **kwargs):
		super(TestHelpers, self).__init__(*args, **kwargs)
		self.test_username = TEST_USERNAME
		self.test_password = TEST_PASSWORD
		self.test_email = TEST_EMAIL


	def setUp(self):
		self.app = create_app(TestConfig)
		self.app_context = self.app.app_context()
		self.app_context.push()
		self.client = self.app.test_client()
		db.create_all()

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
		self.assertEqual(validate_username(r''), 'Username is required')    # empty
		self.assertEqual(validate_username(r' '), 'Username is required')   # space
		self.assertEqual(validate_username(r'	'), 'Username is required') # tab

		self.assertEqual(validate_username(r'invalid!'), 'Username must be alphanumeric')
		self.assertEqual(validate_username(r'invalid@'), 'Username must be alphanumeric')
		self.assertEqual(validate_username(r'invalid_'), 'Username must be alphanumeric')
		self.assertEqual(validate_username(r'#invalid'), 'Username must be alphanumeric')
		self.assertEqual(validate_username(r'$invalid'), 'Username must be alphanumeric')
		self.assertEqual(validate_username(r'%invalid'), 'Username must be alphanumeric')

		self.assertEqual(validate_username(r'a'), 'Username must be at least 3 characters')
		self.assertEqual(validate_username(r'aa'), 'Username must be at least 3 characters')

		self.assertEqual(validate_username(r'a' * 101), 'Username is too long')

		self.assertEqual(validate_username(TEST_USERNAME), 'Username is already taken')

		self.assertEqual(validate_username(r'valid'), None)


	def test_validate_email(self):
		self.assertEqual(validate_email(r''), 'Email is required')

		self.assertEqual(validate_email(r' '), 'Email is invalid')
		self.assertEqual(validate_email(r'	'), 'Email is invalid')
		self.assertEqual(validate_email(r'invalid'), 'Email is invalid')
		self.assertEqual(validate_email(r'invalid@'), 'Email is invalid')
		self.assertEqual(validate_email(r'invalid@invalid'), 'Email is invalid')
		self.assertEqual(validate_email(r'invalid@invalid.'), 'Email is invalid')
		self.assertEqual(validate_email(r'invalid@invalid.c'), 'Email is invalid')
		self.assertEqual(validate_email(r'invalid@@gmail.com'), 'Email is invalid')
		self.assertEqual(validate_email(r'invalid@gmail..com'), 'Email is invalid')

		self.assertEqual(validate_email(r'a' * 101 + '@gmail.com'), 'Email is too long')

		self.assertEqual(validate_email(TEST_EMAIL), 'Email is already taken')

		self.assertEqual(validate_email(r'valid@gmail.com'), None)


	def test_validate_password(self):
		self.assertEqual(validate_password(r'', r'a'), 'Password is required')
		self.assertEqual(validate_password(r'a', r''), 'Confirmation is required')
		self.assertEqual(validate_password(r'', r''), 'Password is required')

		self.assertEqual(validate_password(r'a', r'a'), 'Password must be at least 8 characters')
		self.assertEqual(validate_password(r' ', r' '), 'Password must be at least 8 characters')
		self.assertEqual(validate_password(r'	', r'	'), 'Password must be at least 8 characters')

		self.assertEqual(validate_password(r'a' * 8, r'a' * 8), 'Password is too weak')
		self.assertEqual(validate_password(r'A' * 8, r'A' * 8), 'Password is too weak')
		self.assertEqual(validate_password(r'@' * 8, r'@' * 8), 'Password is too weak')
		self.assertEqual(validate_password(r'1' * 8, r'1' * 8), 'Password is too weak')
		self.assertEqual(validate_password(r'a@' * 8, r'a@' * 8), 'Password is too weak')
		self.assertEqual(validate_password(r'a1' * 8, r'a1' * 8), 'Password is too weak')

		self.assertEqual(validate_password(TEST_PASSWORD, TEST_PASSWORD + 'a'), 'Password and confirmation do not match')
		self.assertEqual(validate_password(TEST_PASSWORD, TEST_PASSWORD), None)


if __name__ == '__main__':
	print("Running tests for helpers...")
	project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
	sys.path.append(project_root)
	unittest.main(testRunner=CustomTextTestRunner())
