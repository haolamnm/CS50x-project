from unittest import main
from pytest import mark
from tests.cases import (
    INVALID_LOGIN_PASSWORD_TEST_CASES,
    INVALID_EMAIL_TEST_CASES,
    INVALID_PASSWORD_TEST_CASES
)
from tests.bases import TestRouteBase


pytestmark = mark.filterwarnings('ignore::DeprecationWarning')


class TestRouteUpdate(TestRouteBase):
    """
    This class contains the test cases for the update route.
    """

    def test_update_email_with_valid_email(self) -> None:
        """
        Test the email update with valid email

        The test will try to update the email with a valid email then check the response.

        :return: None
        """
        self.login(
            email=self.test_email,
            password=self.test_password
        )
        response = self.update_email(
            new_email=self.test_new_email,
            password=self.test_password
        )
        self.check_status_code(response, 200)
        self.check_title(response, 'Profile | Pomodoro 50')
        self.check_flash(response, 'Profile updated successfully', 'success')

        user = self.check_user(
            email=self.test_new_email,
            password=self.test_password
        )
        self.check_session_exists(user)


    def test_update_email_with_invalid_password(self) -> None:
        """
        Test the email update with invalid password

        Each test case will try to update the email with an invalid password then check the response.

        :return: None
        """
        self.login(
            email=self.test_email,
            password=self.test_password
        )
        for password, expected in INVALID_LOGIN_PASSWORD_TEST_CASES:
            with self.subTest(password=password, expected=expected):
                response = self.update_email(
                    new_email=self.test_new_email,
                    password=password
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Profile | Pomodoro 50')
                self.check_flash(response, expected, 'warning')

                user = self.check_user(
                    email=self.test_email,
                    password=self.test_password
                )
                self.check_session_exists(user)


    def test_update_email_with_invalid_email(self) -> None:
        """
        Test the email update with invalid email

        Each test case will try to update the email with an invalid email then check the response.

        :return: None
        """
        self.login(
            email=self.test_email,
            password=self.test_password
        )
        for new_email, expected in INVALID_EMAIL_TEST_CASES:
            with self.subTest(new_email=new_email, expected=expected):
                response = self.update_email(
                    new_email=new_email,
                    password=self.test_password
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Profile | Pomodoro 50')
                self.check_flash(response, expected, 'warning')

                user = self.check_user(
                    email=self.test_email,
                    password=self.test_password
                )
                self.check_session_exists(user)


    def test_update_password_with_valid_new_password(self) -> None:
        """
        Test the password update with valid password

        The test will try to update the password with a valid password then check the response.

        :return: None
        """
        self.login(
            email=self.test_email,
            password=self.test_password
        )
        response = self.update_password(
            new_password=self.test_new_password,
            new_confirmation=self.test_new_password,
            password=self.test_password
        )
        self.check_status_code(response, 200)
        self.check_title(response, 'Profile | Pomodoro 50')
        self.check_flash(response, 'Profile updated successfully', 'success')

        user = self.check_user(
            email=self.test_email,
            password=self.test_new_password
        )
        self.check_session_exists(user)


    def test_update_password_with_invalid_old_password(self) -> None:
        """
        Test the password update with invalid old password

        Each test case will try to update the password with an invalid old password then check the response.

        :return: None
        """
        self.login(
            email=self.test_email,
            password=self.test_password
        )
        for password, expected in INVALID_LOGIN_PASSWORD_TEST_CASES:
            with self.subTest(password=password, expected=expected):
                response = self.update_password(
                    new_password=self.test_new_password,
                    new_confirmation=self.test_new_password,
                    password=password
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Profile | Pomodoro 50')
                self.check_flash(response, expected, 'warning')

                user = self.check_user(
                    email=self.test_email,
                    password=self.test_password
                )
                self.check_session_exists(user)


    def test_update_password_with_invalid_new_password(self) -> None:
        """
        Test the password update with invalid new password

        Each test case will try to update the password with an invalid new password then check the response.

        :return: None
        """
        self.login(
            email=self.test_email,
            password=self.test_password
        )
        for new_password, new_confirmation, expected in INVALID_PASSWORD_TEST_CASES:
            with self.subTest(new_password=new_password, new_confirmation=new_confirmation, expected=expected):
                response = self.update_password(
                    new_password=new_password,
                    new_confirmation=new_confirmation,
                    password=self.test_password
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Profile | Pomodoro 50')
                self.check_flash(response, expected, 'warning')

                user = self.check_user(
                    email=self.test_email,
                    password=self.test_password
                )
                self.check_session_exists(user)


if __name__ == '__main__':
    main()
