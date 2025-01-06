from unittest import main
from pytest import mark
from tests.cases import (
    INCOMPLETED_PROFILE_TEST_CASES,
    INVALID_USERNAME_TEST_CASES,
    INVALID_PASSWORD_TEST_CASES
)
from tests.bases import TestRouteBase


pytestmark = mark.filterwarnings('ignore::DeprecationWarning')


class TestRouteCompleteProfile(TestRouteBase):
    """
    This class contains the test cases for the complete profile route.
    """

    def test_profile_completion_with_valid_data(self) -> None:
       """
       Test the profile completion with valid data

       Each test case will forced register a user, then forced login the user. After that, try to complete the rest of the profile information with valid data.

       :return: None
       """
       for username, email, password in INCOMPLETED_PROFILE_TEST_CASES:
            with self.subTest(username=username, email=email, password=password):
                try:
                    user = self.forced_register(username, email, password)
                    self.forced_login(user)

                    response = self.get('/profile/complete')
                    self.check_status_code(response, 200)
                    self.check_title(response, 'Profile Completion')

                    data = {}
                    if not user.username:
                        data['username'] = self.test_new_username
                    if not user.password:
                        data['password'] = self.test_new_password
                        data['confirmation'] = self.test_new_password

                    response = self.complete_profile(**data)

                    self.check_status_code(response, 200)
                    self.check_title(response, 'Profile')
                    self.check_flash(response, 'Profile completed successfully', 'success')

                    with self.client.session_transaction() as session:
                        id = session['user_id']

                    user = self.check_user(
                        id=id,
                        username=self.test_new_username if 'username' in data else username,
                        email=self.test_new_email,
                        password=self.test_new_password if 'password' in data else password
                    )
                    self.check_session_exists(user)

                except Exception as e:
                    self.forced_rollback()
                    raise e

                finally:
                    with self.client.session_transaction() as session:
                        session.clear()
                    self.forced_rollback()
                    self.forced_delete(user)


    def test_profile_completion_with_invalid_username(self) -> None:
        """
        Test the profile completion with invalid username

        First, forced register a user without a username, then forced login the user. After that, try to complete the username information with invalid data.

        :return: None
        """
        try:
            user = self.forced_register(
                username=None,
				email=self.test_new_email,
				password=self.test_password
			)
            self.forced_login(user)

            response = self.get('/profile/complete')
            self.check_status_code(response, 200)
            self.check_title(response, 'Profile Completion')

            for username, expected in INVALID_USERNAME_TEST_CASES:
                with self.subTest(username=username, expected=expected):
                    response = self.complete_profile(username=username)
                    self.check_status_code(response, 200)
                    self.check_title(response, 'Profile Completion')
                    self.check_flash(response, expected, 'warning')

                    self.assertEqual(user.username, None, 'Username exists')
                    self.check_session_exists(user)

        except Exception as e:
            self.forced_rollback()
            raise e

        finally:
            with self.client.session_transaction() as session:
                session.clear()
            self.forced_rollback()
            self.forced_delete(user)


    def test_profile_completion_with_invalid_password(self) -> None:
        """
        Test the profile completion with invalid password

        First, forced register a user without a password, then forced login the user. After that, try to complete the password information with invalid data.

        :return: None
        """
        try:
            user = self.forced_register(
                username=self.test_new_username,
				email=self.test_new_email,
				password=None
			)
            self.forced_login(user)

            response = self.get('/profile/complete')
            self.check_status_code(response, 200)
            self.check_title(response, 'Profile Completion')

            for password, confirmation, expected in INVALID_PASSWORD_TEST_CASES:
                with self.subTest(password=password, confirmation=confirmation, expected=expected):
                    response = self.complete_profile(password=password, confirmation=confirmation)
                    self.check_status_code(response, 200)
                    self.check_title(response, 'Profile Completion')
                    self.check_flash(response, expected, 'warning')

                    self.assertEqual(user.password, None, 'Password exists')
                    self.check_session_exists(user)

        except Exception as e:
            self.forced_rollback()
            raise e

        finally:
            with self.client.session_transaction() as session:
                session.clear()
            self.forced_rollback()
            self.forced_delete(user)


if __name__ == '__main__':
	main()
