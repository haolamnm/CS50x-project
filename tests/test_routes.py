import unittest
import pytest # type: ignore
from app import create_app, db
from app.models import User
from config import TestConfig
from werkzeug.security import generate_password_hash, check_password_hash
from tests.cases import *


pytestmark = pytest.mark.filterwarnings('ignore::DeprecationWarning')


class TestRoutes(unittest.TestCase):
    def setUp(self):
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

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()


    def register(self, username, email, password, confirmation):
        data = {
            'username': username,
            'email': email,
            'password': password,
            'confirmation': confirmation
        }
        response = self.client.post('/register', data=data, follow_redirects=True)
        return response

    def login(self, login_type, identifier, password):
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

    def logout(self):
        response = self.client.get('/logout', follow_redirects=True)
        return response

    def update(self, update_type, password, new_value, new_confirm_value=None):
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


    def get(self, url):
        response = self.client.get(url)
        return response

    def check_status_code(self, response, status_code):
        self.assertEqual(response.status_code, status_code)

    def check_session(self, user, exists=True):
        if not exists:
            with self.client.session_transaction() as session:
                self.assertNotIn('user_id', session)
                self.assertNotIn('username', session)
                self.assertNotIn('email', session)
        else:
            with self.client.session_transaction() as session:
                self.assertEqual(session['user_id'], user.id)
                self.assertEqual(session['username'], user.username)
                self.assertEqual(session['email'], user.email)

    def check_title(self, response, title):
        self.assertIn(f'<title>\n\t\t\n{title}\n\n\t</title>'.encode(), response.data)

    def check_flash(self, response, message, category):
        if category:
            expected = f'<div class="alert alert-{category} mb-0 text-center" role="alert">\n\t\t\t\t\t\t{message}\n\t\t\t\t\t</div>'
        else:
            raise ValueError('Category is required')
        self.assertIn(expected.encode(), response.data)

    def check_user(self, username: str, email: str, password: str) -> User:
        user = User.query.filter_by(username=username).first()
        self.assertIsNotNone(user)
        self.assertEqual(user.username, username)
        self.assertEqual(user.email, email)
        self.assertTrue(check_password_hash(user.password, password))
        return user


    def test_home(self):
        response = self.get('/')
        self.check_status_code(response, 200)
        self.check_title(response, 'Home')


    def test_login_with_valid_username(self):
        response = self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        self.check_status_code(response, 200)
        self.check_title(response, 'Home')
        self.check_flash(response, 'Logged in successfully', 'success')
        self.check_session(self.test_user)


    def test_login_with_valid_email(self):
        response = self.login(
            login_type='email_login',
            identifier=self.test_email,
            password=self.test_password
        )
        self.check_status_code(response, 200)
        self.check_title(response, 'Home')
        self.check_flash(response, 'Logged in successfully', 'success')
        self.check_session(self.test_user)


    def test_login_with_invalid_username(self):
        for username, expected in INVALID_LOGIN_USERNAME_TEST_CASES:
            response = self.login(
                login_type='username_login',
                identifier=username,
                password=self.test_password
            )
            self.check_status_code(response, 200)
            self.check_title(response, 'Log In')
            self.check_flash(response, expected, 'warning')
            self.check_session(self.test_user, exists=False)


    def test_login_with_invalid_email(self):
        for email, expected in INVALID_LOGIN_EMAIL_TEST_CASES:
            response = self.login(
                login_type='email_login',
                identifier=email,
                password=self.test_password
            )
            self.check_status_code(response, 200)
            self.check_title(response, 'Log In')
            self.check_flash(response, expected, 'warning')
            self.check_session(self.test_user, exists=False)


    def test_login_with_invalid_password(self):
        for password, expected in INVALID_LOGIN_PASSWORD_TEST_CASES:
            response = self.login(
                login_type='username_login',
                identifier=self.test_username,
                password=password
            )
            self.check_status_code(response, 200)
            self.check_title(response, 'Log In')
            self.check_flash(response, expected, 'warning')
            self.check_session(self.test_user, exists=False)


    def test_login_with_invalid_login_type(self):
        response = self.login(
            login_type='invalid_login',
            identifier=self.test_username,
            password=self.test_password
        )
        self.check_status_code(response, 200)
        self.check_title(response, 'Log In')
        self.check_flash(response, 'Invalid login type', 'warning')
        self.check_session(self.test_user, exists=False)


    def test_logout(self):
        self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        response = self.logout()
        self.check_status_code(response, 200)
        self.check_title(response, 'Home')
        self.check_flash(response, 'Logged out successfully', 'success')


    def test_register_with_valid_data(self):
        response = self.register(
            username=self.test_new_username,
            email=self.test_new_email,
            password=self.test_new_password,
            confirmation=self.test_new_password
        )
        self.check_status_code(response, 200)
        self.check_title(response, 'Home')
        self.check_flash(response, 'User registered successfully', 'success')

        user = self.check_user(
            username=self.test_new_username,
            email=self.test_new_email,
            password=self.test_new_password
        )
        self.check_session(user)


    def test_register_with_invalid_username(self):
        for username, expected in INVALID_USERNAME_TEST_CASES:
            response = self.register(
                username=username,
                email=self.test_new_email,
                password=self.test_new_password,
                confirmation=self.test_new_password
            )
            self.check_status_code(response, 200)
            self.check_title(response, 'Register')
            self.check_flash(response, expected, 'warning')
            self.check_session(self.test_user, exists=False)


    def test_register_with_invalid_email(self):
        for email, expected in INVALID_EMAIL_TEST_CASES:
            response = self.register(
                username=self.test_new_username,
                email=email,
                password=self.test_new_password,
                confirmation=self.test_new_password
            )
            self.check_status_code(response, 200)
            self.check_title(response, 'Register')
            self.check_flash(response, expected, 'warning')
            self.check_session(self.test_user, exists=False)


    def test_register_with_invalid_password(self):
        for password, confirmation, expected in INVALID_PASSWORD_TEST_CASES:
            response = self.register(
                username=self.test_new_username,
                email=self.test_new_email,
                password=password,
                confirmation=confirmation
            )
            self.check_status_code(response, 200)
            self.check_title(response, 'Register')
            self.check_flash(response, expected, 'warning')
            self.check_session(self.test_user, exists=False)


    def test_login_required(self):
        for route, expected in LOGIN_REQUIRED_TEST_CASES:
            response = self.get(route)
            self.check_status_code(response, 302)
            if expected == 302:
                self.check_title(response, 'Log In')
                self.check_flash(response, 'Please log in to access this page', 'warning')


    def test_profile(self):
        self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        response = self.get('/profile')
        self.check_status_code(response, 200)
        self.check_title(response, 'Profile')

        self.assertIn(self.test_username.encode(), response.data)
        self.assertIn(self.test_email.encode(), response.data)


    def test_update_username_with_valid_data(self):
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

        user = self.check_user(
            username=self.test_new_username,
            email=self.test_email,
            password=self.test_password
        )
        self.check_session(user)


    def test_update_username_with_invalid_password(self):
        self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        for password, expected in INVALID_LOGIN_PASSWORD_TEST_CASES:
            response = self.update(
                update_type='username_update',
                password=password,
                new_value=self.test_new_username
            )
            self.check_status_code(response, 200)
            self.check_title(response, 'Profile')
            self.check_flash(response, expected, 'warning')

            user = self.check_user(
                username=self.test_username,
                email=self.test_email,
                password=self.test_password
            )
            self.check_session(user)


    def test_update_username_with_invalid_username(self):
        self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        for new_username, expected in INVALID_USERNAME_TEST_CASES:
            response = self.update(
                update_type='username_update',
                password=self.test_password,
                new_value=new_username
            )
            self.check_status_code(response, 200)
            self.check_title(response, 'Profile')
            self.check_flash(response, expected, 'warning')

            user = self.check_user(
                username=self.test_username,
                email=self.test_email,
                password=self.test_password
            )
            self.check_session(user)


    def test_update_email_with_valid_data(self):
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

        user = self.check_user(
            username=self.test_username,
            email=self.test_new_email,
            password=self.test_password
        )
        self.check_session(user)


    def test_update_email_with_invalid_password(self):
        self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        for password, expected in INVALID_LOGIN_PASSWORD_TEST_CASES:
            response = self.update(
                update_type='email_update',
                password=password,
                new_value=self.test_new_email
            )
            self.check_status_code(response, 200)
            self.check_title(response, 'Profile')
            self.check_flash(response, expected, 'warning')
            user = self.check_user(
                username=self.test_username,
                email=self.test_email,
                password=self.test_password
            )
            self.check_session(user)


    def test_update_email_with_invalid_email(self):
        self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )

        for new_email, expected in INVALID_EMAIL_TEST_CASES:
            response = self.update(
                update_type='email_update',
                password=self.test_password,
                new_value=new_email
            )
            self.check_status_code(response, 200)
            self.check_title(response, 'Profile')
            self.check_flash(response, expected, 'warning')

            user = self.check_user(
                username=self.test_username,
                email=self.test_email,
                password=self.test_password
            )
            self.check_session(user)


    def test_update_password_with_valid_data(self):
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

        user = self.check_user(
            username=self.test_username,
            email=self.test_email,
            password=self.test_new_password
        )
        self.check_session(user)


    def test_update_password_with_invalid_old_password(self):
        self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        for password, expected in INVALID_LOGIN_PASSWORD_TEST_CASES:
            response = self.update(
                update_type='password_update',
                password=password,
                new_value=self.test_new_password,
                new_confirm_value=self.test_new_password
            )
            self.check_status_code(response, 200)
            self.check_title(response, 'Profile')
            self.check_flash(response, expected, 'warning')

            user = self.check_user(
                username=self.test_username,
                email=self.test_email,
                password=self.test_password
            )
            self.check_session(user)


    def test_update_password_with_invalid_new_password(self):
        self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        for new_password, new_confirmation, expected in INVALID_PASSWORD_TEST_CASES:
            response = self.update(
                update_type='password_update',
                password=self.test_password,
                new_value=new_password,
                new_confirm_value=new_confirmation
            )
            self.check_status_code(response, 200)
            self.check_title(response, 'Profile')
            self.check_flash(response, expected, 'warning')

            user = self.check_user(
                username=self.test_username,
                email=self.test_email,
                password=self.test_password
            )
            self.check_session(user)


    def test_update_with_invalid_update_type(self):
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

        user = self.check_user(
            username=self.test_username,
            email=self.test_email,
            password=self.test_password
        )
        self.check_session(user)


    def test_page_not_found(self):
        response = self.get('/invalid_page')
        self.check_status_code(response, 404)
        self.check_title(response, '404 Not Found')
        self.check_flash(response, 'Page not found', 'danger')


    # def test_internal_server_error(self):
    #     pass


    # def test_method_not_allowed(self):
    #     pass


    # def test_unauthorized(self):
    #     pass


    # def test_forbidden(self):
    #     pass


    # def test_bad_request(self):
    #     pass


if __name__ == '__main__':
    unittest.main()
