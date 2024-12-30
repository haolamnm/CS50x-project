import unittest
from app.helpers import validate_username, validate_email, validate_password


class TestHelpers(unittest.TestCase):
	def test_validate_username(self):
		self.assertEqual(validate_username(''), 'Username is required')
		self.assertEqual(validate_username('   '), 'Username is required')
		self.assertEqual(validate_username('invalid!'), 'Username must be alphanumeric')
		self.assertEqual(validate_username('invalid@'), 'Username must be alphanumeric')
		self.assertEqual(validate_username('inva lid'), 'Username must be alphanumeric')
		self.assertEqual(validate_username('a'), 'Username must be between 3 and 100 characters')
		self.assertEqual(validate_username('a' * 101), 'Username must be between 3 and 100 characters')
		# self.assertEqual(validate_username('abc'), None)
		# self.assertEqual(validate_username('abc123'), None)

	def test_validate_email(self):
		self.assertEqual(validate_email(''), 'Email is required')
		self.assertEqual(validate_email('invalid'), 'Email is invalid')
		self.assertEqual(validate_email('invalid@'), 'Email is invalid')
		self.assertEqual(validate_email('invalid@invalid'), 'Email is invalid')
		self.assertEqual(validate_email('invalid@invalid.'), 'Email is invalid')
		self.assertEqual(validate_email('invalid@invalid.c'), 'Email is invalid')
		self.assertEqual(validate_email('invalid@@gmail.com'), 'Email is invalid')
		self.assertEqual(validate_email('invalid@gmail..com'), 'Email is invalid')
		self.assertEqual(validate_email('invalid' * 20 + '@gmail.com'), 'We do not accept emails longer than 100 characters')
		# self.assertEqual(validate_email('valid@gmail.com'), None)

	def test_validate_password(self):
		self.assertEqual(validate_password('', 'a'), 'Password is required')
		self.assertEqual(validate_password('a', ''), 'Confirmation is required')
		self.assertEqual(validate_password('', ''), 'Password is required')
		self.assertEqual(validate_password('a', 'a'), 'Password must be at least 8 characters')
		self.assertEqual(validate_password('a' * 8, 'a' * 8), 'Password is too weak')
		self.assertEqual(validate_password('a' * 8 + 'A', 'a' * 8 + 'A'), 'Password is too weak')
		self.assertEqual(validate_password('a' * 8 + 'A1', 'a' * 8 + 'A1'), 'Password is too weak')
		self.assertEqual(validate_password('a#$bz!"A1!.', 'a#$bz!"A1!'), 'Password and confirmation do not match')
		self.assertEqual(validate_password('a#$bz!"A1!.', 'a#$bz!"A1!.'), None)


if __name__ == '__main__':
	unittest.main()
