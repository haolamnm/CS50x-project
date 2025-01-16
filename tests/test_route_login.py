from unittest import main
from pytest import mark
from tests.cases import (
    INVALID_LOGIN_EMAIL_TEST_CASES,
    INVALID_LOGIN_PASSWORD_TEST_CASES
)
from tests.bases import TestRouteBase


pytestmark = mark.filterwarnings('ignore::DeprecationWarning')


class TestRouteLogin(TestRouteBase):
    """
    This class contains the test cases for the login route.
    """

    def test_login_with_valid_email(self) -> None:
        """
        Test the login with valid email

        The test will try to login with a valid email then check the response.

        :return: None
        """
        response = self.login(
            email=self.test_email,
            password=self.test_password
        )
        self.check_status_code(response, 200)
        self.check_title(response, 'Home | Pomodoro 50')
        self.check_flash(response, 'Logged in successfully', 'success')
        self.check_session_exists(self.test_user)


    def test_login_with_invalid_email(self) -> None:
        """
        Test the login route with invalid email

        Each test case will try to login with an invalid email then check the response.

        :return: None
        """
        for email, expected in INVALID_LOGIN_EMAIL_TEST_CASES:
            with self.subTest(email=email, expected=expected):
                response = self.login(
                    email=email,
                    password=self.test_password
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Log In | Pomodoro 50')
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
                    email=self.test_email,
                    password=password
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Log In | Pomodoro 50')
                self.check_flash(response, expected, 'warning')
                self.check_session_absent()


if __name__ == '__main__':
    main()
