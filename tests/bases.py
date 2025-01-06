from app import create_app
from app.extensions import db
from app.models import User
from app.config import TestConfig
from unittest import TestCase
from pytest import mark
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.test import TestResponse
from tests.cases import *


pytestmark = mark.filterwarnings('ignore::DeprecationWarning')


class TestRouteBase(TestCase):
    """
    This class in the base class for all other test classes.

    It contains the needed methods for testing the routes.
    """

    def setUp(self) -> None:
        """
        Set up the test environment, test user and test client.

        :return: None
        """
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = self.app.test_client()
        db.create_all()

        self.test_username = TEST_USERNAME
        self.test_password = TEST_PASSWORD
        self.test_email = TEST_EMAIL
        self.test_new_username = TEST_NEW_USERNAME
        self.test_new_password = TEST_NEW_PASSWORD
        self.test_new_email = TEST_NEW_EMAIL

        self.test_user = User(
            username=self.test_username,
            email=self.test_email,
            password=generate_password_hash(self.test_password, salt_length=16)
        )
        db.session.add(self.test_user)
        db.session.commit()

        with self.client.session_transaction() as session:
            session.clear()

    def tearDown(self) -> None:
        """
        Clean up the test environment.

        :return: None
        """
        db.session.rollback()
        db.session.remove()
        db.drop_all()
        self.app_context.pop()


    def register(self, username: str, email: str, password: str, confirmation: str) -> TestResponse:
        """
        Register a new user through the registration route (/register).

        :param username: The username of the user
        :param email: The email of the user
        :param password: The password of the user
        :param confirmation: The password confirmation of the user
        :return: The response from the registration route
        """
        data = {
            'username': username,
            'email': email,
            'password': password,
            'confirmation': confirmation
        }
        response = self.client.post('/register', data=data, follow_redirects=True)
        return response

    def forced_register(self, username: str, email: str, password: str) -> User:
        """
        Explicitly create a new user in the database.

        :param username: The username of the user
        :param email: The email of the user
        :param password: The password of the user
        :return: The user object
        """
        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password, salt_length=16) if password else None
        )
        db.session.add(user)
        db.session.commit()
        return user


    def login(self, login_type: str, identifier: str, password: str) -> TestResponse:
        """
        Log in the user through the login route (/login).

        :param login_type: The type of login (username_login or email_login)
        :param identifier: The username or email of the user
        :param password: The password of the user
        :return: The response from the login route
        """
        data = {
            'login_type': login_type,
            'password': password
        }
        if login_type == 'username_login':
            data['username'] = identifier
        elif login_type == 'email_login':
            data['email'] = identifier
        response = self.client.post('/login', data=data, follow_redirects=True)
        return response

    def forced_login(self, user: User) -> None:
        """
        Explicitly log in the user by adding user to the session.

        :param user: The user object
        :return: None
        """
        with self.client.session_transaction() as session:
            session['user_id'] = user.id
            session['username'] = user.username
            session['email'] = user.email
            session['oauth_provider'] = user.oauth_provider


    def logout(self) -> TestResponse:
        """
        Log out the user through the logout route (/logout).

        :return: The response from the logout route
        """
        response = self.client.get('/logout', follow_redirects=True)
        return response


    def update(self, update_type: str, password: str, new_value: str, new_confirm_value: str = None) -> TestResponse:
        """
        Update user information through the update route (/update).

        :param update_type: The type of update (username_update, email_update or password_update)
        :param password: The password of the user
        :param new_value: The new value to update
        :param new_confirm_value: The new confirmation value to update
        :return: The response from the update route
        """
        data = {
            'update_type': update_type,
            'password': password
        }
        if update_type == 'username_update':
            data['new_username'] = new_value
        elif update_type == 'email_update':
            data['new_email'] = new_value
        elif update_type == 'password_update':
            data['new_password'] = new_value
            data['new_confirmation'] = new_confirm_value
        response = self.client.post('/update', data=data, follow_redirects=True)
        return response


    def get(self, route: str, follow_redirects: bool = False) -> TestResponse:
        """
        Get the response from a route.

        :param route: The route to get the response from
        :param follow_redirects: Whether to follow redirects or not
        """
        response = self.client.get(route, follow_redirects=follow_redirects)
        return response


    def complete_profile(self, username: str = None, password: str = None, confirmation: str = None) -> TestResponse:
        """
        Complete the user profile through the complete profile route (/profile/complete).

        :param username: The username of the user
        :param password: The password of the user
        :param confirmation: The password confirmation of the user
        :return: The response from the complete profile route
        """
        data = {}
        if username is not None:
            data['username'] = username
        if password is not None:
            data['password'] = password
        if confirmation is not None:
            data['confirmation'] = confirmation
        response = self.client.post('/profile/complete', data=data, follow_redirects=True)
        return response


    def check_status_code(self, response: TestResponse, status_code: int) -> None:
        """
        Check if the status code matches the expected status code.

        :param response: The response to check
        :param status_code: The expected status code
        :return: None
        """
        self.assertEqual(response.status_code, status_code, 'Status code does not match')

    def check_session_exists(self, user: User, oauth_provider: str = 'local') -> None:
        """
        Check if the user information already exists in the session.
        Check if the information in the session matches the user information.

        :param user: The user object
        :param oauth_provider: The OAuth provider
        :return: None
        """
        with self.client.session_transaction() as session:
            self.assertEqual(session['user_id'], user.id, 'User ID does not match')
            self.assertEqual(session['username'], user.username, 'Username does not match')
            self.assertEqual(session['email'], user.email, 'Email does not match')
            self.assertEqual(session['oauth_provider'], oauth_provider, 'OAuth provider does not match')

    def check_session_absent(self) -> None:
        """
        Explicitly check if the user information does not exist in the session.

        :return: None
        """
        with self.client.session_transaction() as session:
            self.assertNotIn('user_id', session, 'User ID exists')
            self.assertNotIn('username', session, 'Username exists')
            self.assertNotIn('email', session, 'Email exists')
            self.assertNotIn('oauth_provider', session, 'OAuth provider exists')

    def check_title(self, response: TestResponse, title: str) -> None:
        """
        Check if the current page title matches the expected title.

        :param response: The response to check
        :param title: The expected title
        :return: None
        """
        self.assertIn(f'<title>\n\t\t\n{title}\n\n\t</title>'.encode(), response.data, 'Title does not match')

    def check_flash(self, response: TestResponse, message: str, category: str) -> None:
        """
        Check if the flash appears on the page matches the expected flash message.

        :param response: The response to check
        :param message: The expected message
        :param category: The expected category
        :return: None
        """
        expected = f'<div class="alert alert-{category} mb-0 text-center" role="alert">\n\t\t\t\t\t\t{message}\n\t\t\t\t\t</div>'
        self.assertIn(expected.encode(), response.data, 'Flash message does not match')

    def check_user(self, id: int = None, username: str = None, email: str = None, password: str = None) -> User | None:
        """
        Check if the user exists in the database.
        Then check if the user information matches the expected given information.
        After that, return the user object if it exists. Otherwise, return None.

        :param id: The user ID
        :param username: The username of the user
        :param email: The email of the user
        :param password: The password of the user
        :return: The user object if it exists, None otherwise
        """
        if id is not None:
            user = User.query.get(id)
        elif username is not None:
            user = User.query.filter_by(username=username).first()
        elif email is not None:
            user = User.query.filter_by(email=email).first()
        else:
            self.fail('No identifier provided')
            return None

        self.assertIsNotNone(user, 'User does not exist')

        if username is not None:
            self.assertEqual(user.username, username, 'Username does not match')
        if email is not None:
            self.assertEqual(user.email, email, 'Email does not match')
        if password is not None:
            self.assertTrue(check_password_hash(user.password, password), 'Password does not match')
        return user

    def check_redirect_route(self, response: str, route: str) -> None:
        """
        Check if the redirect route matches the expected route.

        :param response: The response to check
        :param route: The expected route
        :return: None
        """
        self.assertIn(route, response.headers['Location'], 'Route does not match')


    def forced_delete(self, user: User) -> None:
        """
        Explicitly delete the user from the database.

        :param user: The user object
        :return: None
        """
        db.session.delete(user)
        db.session.commit()

    def forced_rollback(self) -> None:
        """
        Explicitly rollback the database session.

        :return: None
        """
        db.session.rollback()


if __name__ == '__main__':
	pass
