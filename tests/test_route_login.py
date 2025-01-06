from unittest import main
from pytest import mark
from tests.cases import (
    INVALID_LOGIN_USERNAME_TEST_CASES,
    INVALID_LOGIN_EMAIL_TEST_CASES,
    INVALID_LOGIN_PASSWORD_TEST_CASES
)
from tests.bases import TestRouteBase


pytestmark = mark.filterwarnings('ignore::DeprecationWarning')


class TestRouteLogin(TestRouteBase):
    """
    This class contains the test cases for the login route.
    """

    def test_login_with_valid_username(self) -> None:
        """
        Test the login with valid username

        The test will try to login with a valid username then check the response.

        :return: None
        """
        response = self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        self.check_status_code(response, 200)
        self.check_title(response, 'Home')
        self.check_flash(response, 'Logged in successfully', 'success')
        self.check_session_exists(self.test_user)


    def test_login_with_valid_email(self) -> None:
        """
        Test the login with valid email

        The test will try to login with a valid email then check the response.

        :return: None
        """
        response = self.login(
            login_type='email_login',
            identifier=self.test_email,
            password=self.test_password
        )
        self.check_status_code(response, 200)
        self.check_title(response, 'Home')
        self.check_flash(response, 'Logged in successfully', 'success')
        self.check_session_exists(self.test_user)


    def test_login_with_invalid_username(self) -> None:
        """
        Test the login route with invalid username

        Each test case will try to login with an invalid username then check the response.

        :return: None
        """
        for username, expected in INVALID_LOGIN_USERNAME_TEST_CASES:
            with self.subTest(username=username, expected=expected):
                response = self.login(
                    login_type='username_login',
                    identifier=username,
                    password=self.test_password
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Log In')
                self.check_flash(response, expected, 'warning')
                self.check_session_absent()


    def test_login_with_invalid_email(self) -> None:
        """
        Test the login route with invalid email

        Each test case will try to login with an invalid email then check the response.

        :return: None
        """
        for email, expected in INVALID_LOGIN_EMAIL_TEST_CASES:
            with self.subTest(email=email, expected=expected):
                response = self.login(
                    login_type='email_login',
                    identifier=email,
                    password=self.test_password
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Log In')
                self.check_flash(response, expected, 'warning')
                self.check_session_absent()


    def test_login_with_invalid_password(self) -> None:
        """
        Test the login route with invalid password

        Each test case will try to login with an invalid password then check the response.

        :return: None
        """
        for password, expected in INVALID_LOGIN_PASSWORD_TEST_CASES:
            with self.subTest(password=password, expected=expected):
                response = self.login(
                    login_type='username_login',
                    identifier=self.test_username,
                    password=password
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Log In')
                self.check_flash(response, expected, 'warning')
                self.check_session_absent()


    def test_login_with_invalid_login_type(self) -> None:
        """
        Test the login route with invalid login type

        The test will try to login with an invalid login type then check the response.

        :return: None
        """
        response = self.login(
            login_type='invalid_login',
            identifier=self.test_username,
            password=self.test_password
        )
        self.check_status_code(response, 200)
        self.check_title(response, 'Log In')
        self.check_flash(response, 'Invalid login type', 'warning')
        self.check_session_absent()


if __name__ == '__main__':
    main()
