from unittest import main
from pytest import mark
from tests.cases import (
    INVALID_LOGIN_PASSWORD_TEST_CASES,
    INVALID_USERNAME_TEST_CASES,
    INVALID_EMAIL_TEST_CASES,
    INVALID_PASSWORD_TEST_CASES
)
from tests.bases import TestRouteBase


pytestmark = mark.filterwarnings('ignore::DeprecationWarning')


class TestRouteUpdate(TestRouteBase):
    """
    This class contains the test cases for the update route.
    """

    def test_update_username_with_valid_username(self) -> None:
        """
        Test the username update with valid username

        The test will try to update the username with a valid username then check the response.

        :return: None
        """
        self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        response = self.update(
            update_type='username_update',
            password=self.test_password,
            new_value=self.test_new_username
        )
        self.check_status_code(response, 200)
        self.check_title(response, 'Profile')
        self.check_flash(response, 'Profile updated successfully', 'success')

        with self.client.session_transaction() as session:
            id = session['user_id']

        user = self.check_user(
            id=id,
            username=self.test_new_username,
            email=self.test_email,
            password=self.test_password
        )
        self.check_session_exists(user)


    def test_update_username_with_invalid_password(self) -> None:
        """
        Test the username update with invalid password

        Each test case will try to update the username with an invalid password then check the response.

        :return: None
        """
        self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        for password, expected in INVALID_LOGIN_PASSWORD_TEST_CASES:
            with self.subTest(password=password, expected=expected):
                response = self.update(
                    update_type='username_update',
                    password=password,
                    new_value=self.test_new_username
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Profile')
                self.check_flash(response, expected, 'warning')

                with self.client.session_transaction() as session:
                    id = session['user_id']

                user = self.check_user(
                    id=id,
                    username=self.test_username,
                    email=self.test_email,
                    password=self.test_password
                )
                self.check_session_exists(user)


    def test_update_username_with_invalid_username(self) -> None:
        """
        Test the username update with invalid username

        Each test case will try to update the username with an invalid username then check the response.

        :return: None
        """
        self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        for new_username, expected in INVALID_USERNAME_TEST_CASES:
            with self.subTest(new_username=new_username, expected=expected):
                response = self.update(
                    update_type='username_update',
                    password=self.test_password,
                    new_value=new_username
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Profile')
                self.check_flash(response, expected, 'warning')

                with self.client.session_transaction() as session:
                    id = session['user_id']

                user = self.check_user(
                    id=id,
                    username=self.test_username,
                    email=self.test_email,
                    password=self.test_password
                )
                self.check_session_exists(user)


    def test_update_email_with_valid_email(self) -> None:
        """
        Test the email update with valid email

        The test will try to update the email with a valid email then check the response.

        :return: None
        """
        self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        response = self.update(
            update_type='email_update',
            password=self.test_password,
            new_value=self.test_new_email
        )
        self.check_status_code(response, 200)
        self.check_title(response, 'Profile')
        self.check_flash(response, 'Profile updated successfully', 'success')

        with self.client.session_transaction() as session:
            id = session['user_id']

        user = self.check_user(
            id=id,
            username=self.test_username,
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
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        for password, expected in INVALID_LOGIN_PASSWORD_TEST_CASES:
            with self.subTest(password=password, expected=expected):
                response = self.update(
                    update_type='email_update',
                    password=password,
                    new_value=self.test_new_email
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Profile')
                self.check_flash(response, expected, 'warning')

                with self.client.session_transaction() as session:
                    id = session['user_id']

                user = self.check_user(
                    id=id,
                    username=self.test_username,
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
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        for new_email, expected in INVALID_EMAIL_TEST_CASES:
            with self.subTest(new_email=new_email, expected=expected):
                response = self.update(
                    update_type='email_update',
                    password=self.test_password,
                    new_value=new_email
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Profile')
                self.check_flash(response, expected, 'warning')

                with self.client.session_transaction() as session:
                    id = session['user_id']

                user = self.check_user(
                    id=id,
                    username=self.test_username,
                    email=self.test_email,
                    password=self.test_password
                )
                self.check_session_exists(user)


    def test_update_password_with_valid_password(self) -> None:
        """
        Test the password update with valid password

        The test will try to update the password with a valid password then check the response.

        :return: None
        """
        self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        response = self.update(
            update_type='password_update',
            password=self.test_password,
            new_value=self.test_new_password,
            new_confirm_value=self.test_new_password
        )
        self.check_status_code(response, 200)
        self.check_title(response, 'Profile')
        self.check_flash(response, 'Profile updated successfully', 'success')

        with self.client.session_transaction() as session:
            id = session['user_id']

        user = self.check_user(
            id=id,
            username=self.test_username,
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
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        for password, expected in INVALID_LOGIN_PASSWORD_TEST_CASES:
            with self.subTest(password=password, expected=expected):
                response = self.update(
                    update_type='password_update',
                    password=password,
                    new_value=self.test_new_password,
                    new_confirm_value=self.test_new_password
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Profile')
                self.check_flash(response, expected, 'warning')

                with self.client.session_transaction() as session:
                    id = session['user_id']

                user = self.check_user(
                    id=id,
                    username=self.test_username,
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
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        for new_password, new_confirmation, expected in INVALID_PASSWORD_TEST_CASES:
            with self.subTest(new_password=new_password, new_confirmation=new_confirmation, expected=expected):
                response = self.update(
                    update_type='password_update',
                    password=self.test_password,
                    new_value=new_password,
                    new_confirm_value=new_confirmation
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Profile')
                self.check_flash(response, expected, 'warning')

                with self.client.session_transaction() as session:
                    id = session['user_id']

                user = self.check_user(
                    id=id,
                    username=self.test_username,
                    email=self.test_email,
                    password=self.test_password
                )
                self.check_session_exists(user)


    def test_update_with_invalid_update_type(self) -> None:
        """
        Test the update route with invalid update type (not username, email, or password)

        The test will try to update the profile with an invalid update type then check the response.

        :return: None
        """
        self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        response = self.update(
            update_type='invalid_update',
            password=self.test_password,
            new_value=self.test_new_username
        )
        self.check_status_code(response, 200)
        self.check_title(response, 'Profile')
        self.check_flash(response, 'Invalid update type', 'warning')

        with self.client.session_transaction() as session:
            id = session['user_id']

        user = self.check_user(
            id=id,
            username=self.test_username,
            email=self.test_email,
            password=self.test_password
        )
        self.check_session_exists(user)


if __name__ == '__main__':
    main()
