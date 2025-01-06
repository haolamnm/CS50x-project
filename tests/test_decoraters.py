from unittest import main
from pytest import mark
from tests.cases import (
    LOGIN_REQUIRED_TEST_CASES,
    INCOMPLETED_PROFILE_TEST_CASES
)
from tests.bases import TestRouteBase


pytestmark = mark.filterwarnings('ignore::DeprecationWarning')


class TestDecorators(TestRouteBase):
    """
    This class contains the test cases for the decorators.
    """

    def test_login_required(self) -> None:
        """
        Test the @login_required decorator

        The test will try to access the routes that requires a login. The expected result is a redirect to the login page.

        :return: None
        """
        for route, expected in LOGIN_REQUIRED_TEST_CASES:
            with self.subTest(route=route, expected=expected):
                response = self.get(route)
                self.check_status_code(response, 302)

                response = self.get(route, follow_redirects=True)
                self.check_title(response, 'Log In')
                self.check_flash(response, 'Please login to access this page', 'warning')
                self.check_session_absent()


    def test_profile_completed_required_with_incompleted_profile(self) -> None:
        """
        Test the @profile_completed_required decorator with an incompleted profile

        Each test case will forced register an incompleted user profile, then forced login the user. After that, try to access the routes that requires a completed profile.

        :return: None
        """
        for username, email, password in INCOMPLETED_PROFILE_TEST_CASES:
            with self.subTest(username=username, email=email, password=password):
                try:
                    user = self.forced_register(username, email, password)

                    self.forced_login(user)

                    for route, _ in LOGIN_REQUIRED_TEST_CASES:
                        response = self.get(route)
                        self.check_status_code(response, 302)
                        self.check_redirect_route(response, '/profile/complete')

                        response = self.get(route, follow_redirects=True)
                        self.check_status_code(response, 200)
                        self.check_title(response, 'Profile Completion')
                        self.check_flash(response, 'Please complete your profile before proceeding', 'warning')

                except Exception as e:
                    self.forced_rollback()
                    raise e

                finally:
                    with self.client.session_transaction() as session:
                        session.clear()
                    self.forced_rollback()
                    self.forced_delete(user)


    def test_profile_completed_requriement_with_completed_profile(self) -> None:
        """
        Test the @profile_completed_required decorator with a completed profile

        The test will log a user in, then try to access the routes that requires a completed profile. The expected result is a redirect to the profile page.

        :return: None
        """
        self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        response = self.get('/profile/complete')
        self.check_status_code(response, 302)
        self.check_redirect_route(response, '/profile')

        response = self.get('/profile', follow_redirects=True)
        self.check_status_code(response, 200)
        self.check_title(response, 'Profile')
        self.check_flash(response, 'Profile is already complete', 'info')


if __name__ == '__main__':
	main()
