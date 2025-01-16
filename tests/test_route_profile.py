from unittest import main
from pytest import mark
from tests.cases import INVALID_PASSWORD_TEST_CASES
from tests.bases import TestRouteBase


pytestmark = mark.filterwarnings('ignore::DeprecationWarning')


class TestRouteCompleteProfile(TestRouteBase):
    """
    This class contains the test cases for the complete profile route.
    """

    def test_profile_complete_password_with_valid_password(self) -> None:
        """
        Test the profile complete password with valid password

        Each test case will forced register a user, then forced login the user. After that, try to complete the password information with valid data.

        :return: None
        """
        user = self.forced_signup(
            email=self.test_new_email,
            password=None
        )
        self.forced_login(user)

        response = self.get('/profile/complete/password')
        self.check_status_code(response, 200)
        self.check_title(response, 'Complete Password | Pomodoro 50')

        response = self.complete_password(
            password=self.test_new_password,
            confirmation=self.test_new_password
        )

        self.check_status_code(response, 200)
        self.check_title(response, 'Profile | Pomodoro 50')
        self.check_flash(response, 'Profile completed successfully', 'success')
        user = self.check_user(
            email=self.test_new_email,
            password=self.test_new_password
        )
        self.check_session_exists(user)


    def test_profile_complete_password_with_invalid_password(self) -> None:
        """
        Test the profile completion with invalid password

        First, forced register a user without a password, then forced login the user. After that, try to complete the password information with invalid data.

        :return: None
        """
        try:
            user = self.forced_signup(
				email=self.test_new_email,
				password=None
			)
            self.forced_login(user)

            response = self.get('/profile/complete/password')
            self.check_status_code(response, 200)
            self.check_title(response, 'Complete Password | Pomodoro 50')

            for password, confirmation, expected in INVALID_PASSWORD_TEST_CASES:
                with self.subTest(password=password, confirmation=confirmation, expected=expected):
                    response = self.complete_password(
                        password=password,
                        confirmation=confirmation
                    )
                    self.check_status_code(response, 200)
                    self.check_title(response, 'Complete Password | Pomodoro 50')
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
