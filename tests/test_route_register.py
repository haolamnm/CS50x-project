from unittest import main
from pytest import mark
from tests.cases import (
    INVALID_USERNAME_TEST_CASES,
    INVALID_EMAIL_TEST_CASES,
    INVALID_PASSWORD_TEST_CASES
)
from tests.bases import TestRouteBase


pytestmark = mark.filterwarnings('ignore::DeprecationWarning')


class TestRouteRegister(TestRouteBase):
    """
    Test the handling of the register route
    """

    def test_register_with_valid_data(self) -> None:
        """
        Test the registration route with valid data

        The test will try to register a new user with valid data then check the response.

        :return: None
        """
        response = self.register(
            username=self.test_new_username,
            email=self.test_new_email,
            password=self.test_new_password,
            confirmation=self.test_new_password
        )
        self.check_status_code(response, 200)
        self.check_title(response, 'Home')
        self.check_flash(response, 'User registered successfully', 'success')

        with self.client.session_transaction() as session:
            id = session['user_id']

        user = self.check_user(
            id=id,
            username=self.test_new_username,
            email=self.test_new_email,
            password=self.test_new_password
        )
        self.check_session_exists(user)


    def test_register_with_invalid_username(self) -> None:
        """
        Test the registration route with invalid username

        Each test case will try to register a new user with an invalid username then check the response.

        :return: None
        """
        for username, expected in INVALID_USERNAME_TEST_CASES:
            with self.subTest(username=username, expected=expected):
                response = self.register(
                    username=username,
                    email=self.test_new_email,
                    password=self.test_new_password,
                    confirmation=self.test_new_password
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Register')
                self.check_flash(response, expected, 'warning')
                self.check_session_absent()


    def test_register_with_invalid_email(self) -> None:
        """
        Test the registration route with invalid email

        Each test case will try to register a new user with an invalid email then check the response.

        :return: None
        """
        for email, expected in INVALID_EMAIL_TEST_CASES:
            with self.subTest(email=email, expected=expected):
                response = self.register(
                    username=self.test_new_username,
                    email=email,
                    password=self.test_new_password,
                    confirmation=self.test_new_password
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Register')
                self.check_flash(response, expected, 'warning')
                self.check_session_absent()


    def test_register_with_invalid_password(self) -> None:
        """
        Test the registration route with invalid password

        Each test case will try to register a new user with an invalid password then check the response.

        :return: None
        """
        for password, confirmation, expected in INVALID_PASSWORD_TEST_CASES:
            with self.subTest(password=password, confirmation=confirmation, expected=expected):
                response = self.register(
                    username=self.test_new_username,
                    email=self.test_new_email,
                    password=password,
                    confirmation=confirmation
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Register')
                self.check_flash(response, expected, 'warning')
                self.check_session_absent()


if __name__ == '__main__':
    main()
