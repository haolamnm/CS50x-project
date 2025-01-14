from unittest import main
from pytest import mark
from app.helpers import (
	validate_email,
	validate_password
)
from tests.cases import (
	INVALID_EMAIL_TEST_CASES,
	INVALID_PASSWORD_TEST_CASES,
	TEST_PASSWORD
)
from tests.bases import TestRouteBase


pytestmark = mark.filterwarnings('ignore::DeprecationWarning')


class TestHelpers(TestRouteBase):
	"""
	This class contains the test cases for the helper functions.
	"""

	def test_validate_email(self) -> None:
		"""
		Test the validate_email function

		Each test case will validate the email using the function. The expected result is the error message.

		:return: None
		"""
		for email, error in INVALID_EMAIL_TEST_CASES:
			with self.subTest(email=email, error=error):
				self.assertEqual(validate_email(email), error)

		self.assertEqual(validate_email(r'valid@gmail.com'), None)


	def test_validate_password(self) -> None:
		"""
		Test the validate_password function

		Each test case will validate the password using the function. The expected result is the error message.

		:return: None
		"""
		for password, confirmation, error in INVALID_PASSWORD_TEST_CASES:
			with self.subTest(password=password, confirmation=confirmation, error=error):
				self.assertEqual(validate_password(password, confirmation), error)

		self.assertEqual(validate_password(TEST_PASSWORD, TEST_PASSWORD), None)


if __name__ == '__main__':
	main()
