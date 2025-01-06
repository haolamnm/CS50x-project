from unittest import main
from pytest import mark
from tests.bases import TestRouteBase


pytestmark = mark.filterwarnings('ignore::DeprecationWarning')


class TestRouteLogout(TestRouteBase):
    """
    This class contains the test cases for the logout route.
    """
    def test_logout(self) -> None:
        """
        Test the logout route

        The test will try to logout the user then check the response.

        :return: None
        """
        self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        response = self.logout()
        self.check_status_code(response, 200)
        self.check_title(response, 'Home')
        self.check_flash(response, 'Logged out successfully', 'success')
        self.check_session_absent()


if __name__ == '__main__':
	main()
