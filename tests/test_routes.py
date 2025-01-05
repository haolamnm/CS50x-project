from app import create_app
from app.extensions import db
from app.models import User
from unittest import TestCase, main
from pytest import mark
from app.config import TestConfig
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.test import TestResponse
from tests.cases import *


pytestmark = mark.filterwarnings('ignore::DeprecationWarning')


class TestRoutes(TestCase):
    def setUp(self) -> None:
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
        db.session.rollback()
        db.session.remove()
        db.drop_all()
        self.app_context.pop()


    def register(self, username: str, email: str, password: str, confirmation: str) -> TestResponse:
        data = {
            'username': username,
            'email': email,
            'password': password,
            'confirmation': confirmation
        }
        response = self.client.post('/register', data=data, follow_redirects=True)
        return response

    def login(self, login_type: str, identifier: str, password: str) -> TestResponse:
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

    def logout(self) -> TestResponse:
        response = self.client.get('/logout', follow_redirects=True)
        return response

    def update(self, update_type: str, password: str, new_value: str, new_confirm_value: str=None) -> TestResponse:
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

    def get(self, route: str, follow_redirects: bool=False) -> TestResponse:
        response = self.client.get(route, follow_redirects=follow_redirects)
        return response

    def profile_complete(self, username: str=None, password: str=None, confirmation: str=None) -> TestResponse:
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
        """Check if the status code matches the expected status code"""
        self.assertEqual(response.status_code, status_code, 'Status code does not match')

    def check_session_exists(self, user: User, oauth_provider: str='local') -> None:
        """Check if the session exists"""
        with self.client.session_transaction() as session:
            self.assertEqual(session['user_id'], user.id, 'User ID does not match')
            self.assertEqual(session['username'], user.username, 'Username does not match')
            self.assertEqual(session['email'], user.email, 'Email does not match')
            self.assertEqual(session['oauth_provider'], oauth_provider, 'OAuth provider does not match')

    def check_session_absent(self) -> None:
        """Check if the session is empty"""
        with self.client.session_transaction() as session:
            self.assertNotIn('user_id', session, 'User ID exists')
            self.assertNotIn('username', session, 'Username exists')
            self.assertNotIn('email', session, 'Email exists')
            self.assertNotIn('oauth_provider', session, 'OAuth provider exists')

    def check_title(self, response: TestResponse, title: str) -> None:
        """Check if the title matches the expected title"""
        self.assertIn(f'<title>\n\t\t\n{title}\n\n\t</title>'.encode(), response.data, 'Title does not match')

    def check_flash(self, response: TestResponse, message: str, category: str) -> None:
        expected = f'<div class="alert alert-{category} mb-0 text-center" role="alert">\n\t\t\t\t\t\t{message}\n\t\t\t\t\t</div>'
        self.assertIn(expected.encode(), response.data, 'Flash message does not match')

    def check_user(self, id: int=None, username: str=None, email: str=None, password: str=None) -> User:
        """Check if user exists in the database"""
        if id is not None:
            user = User.query.get(id)
        elif username is not None:
            user = User.query.filter_by(username=username).first()
        elif email is not None:
            user = User.query.filter_by(email=email).first()
        else:
            self.fail('No identifier provided')

        self.assertIsNotNone(user, 'User does not exist')

        if username is not None:
            self.assertEqual(user.username, username, 'Username does not match')
        if email is not None:
            self.assertEqual(user.email, email, 'Email does not match')
        if password is not None:
            self.assertTrue(check_password_hash(user.password, password), 'Password does not match')
        return user

    def check_route(self, response: str, route: str) -> None:
        """Check if the route matches the expected route"""
        self.assertIn(route, response.headers['Location'], 'Route does not match')


    def test_home(self) -> None:
        response = self.get('/')
        self.check_status_code(response, 200)
        self.check_title(response, 'Home')


    def test_login_with_valid_username(self) -> None:
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
        response = self.login(
            login_type='invalid_login',
            identifier=self.test_username,
            password=self.test_password
        )
        self.check_status_code(response, 200)
        self.check_title(response, 'Log In')
        self.check_flash(response, 'Invalid login type', 'warning')
        self.check_session_absent()


    def test_logout(self) -> None:
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


    def test_register_with_valid_data(self) -> None:
        response = self.register(
            username=self.test_new_username,
            email=self.test_new_email,
            password=self.test_new_password,
            confirmation=self.test_new_password
        )
        self.check_status_code(response, 200)
        self.check_title(response, 'Home')
        self.check_flash(response, 'User registered successfully', 'success')

        with self.client.session_transaction() as session:
            id = session['user_id']

        user = self.check_user(
            id=id,
            username=self.test_new_username,
            email=self.test_new_email,
            password=self.test_new_password
        )
        self.check_session_exists(user)


    def test_register_with_invalid_username(self) -> None:
        for username, expected in INVALID_USERNAME_TEST_CASES:
            with self.subTest(username=username, expected=expected):
                response = self.register(
                    username=username,
                    email=self.test_new_email,
                    password=self.test_new_password,
                    confirmation=self.test_new_password
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Register')
                self.check_flash(response, expected, 'warning')
                self.check_session_absent()


    def test_register_with_invalid_email(self) -> None:
        for email, expected in INVALID_EMAIL_TEST_CASES:
            with self.subTest(email=email, expected=expected):
                response = self.register(
                    username=self.test_new_username,
                    email=email,
                    password=self.test_new_password,
                    confirmation=self.test_new_password
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Register')
                self.check_flash(response, expected, 'warning')
                self.check_session_absent()


    def test_register_with_invalid_password(self) -> None:
        for password, confirmation, expected in INVALID_PASSWORD_TEST_CASES:
            with self.subTest(password=password, confirmation=confirmation, expected=expected):
                response = self.register(
                    username=self.test_new_username,
                    email=self.test_new_email,
                    password=password,
                    confirmation=confirmation
                )
                self.check_status_code(response, 200)
                self.check_title(response, 'Register')
                self.check_flash(response, expected, 'warning')
                self.check_session_absent()


    def test_login_required(self) -> None:
        for route, expected in LOGIN_REQUIRED_TEST_CASES:
            with self.subTest(route=route, expected=expected):
                response = self.get(route)
                self.check_status_code(response, 302)

                response = self.get(route, follow_redirects=True)
                self.check_title(response, 'Log In')
                self.check_flash(response, 'Please login to access this page', 'warning')
                self.check_session_absent()


    def test_profile(self) -> None:
        self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        response = self.get('/profile')
        self.check_status_code(response, 200)
        self.check_title(response, 'Profile')


    def test_update_username_with_valid_username(self) -> None:
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


    def test_page_not_found(self) -> None:
        response = self.get('/invalid_page')
        self.check_status_code(response, 404)
        self.check_title(response, '404 Not Found')
        self.check_flash(response, 'Page not found', 'danger')
        self.check_session_absent()


    def test_login_with_google(self) -> None:
        response = self.get('/login/google')
        self.check_status_code(response, 302) # Redirect to Google login page
        self.check_route(response, 'https://accounts.google.com/o/oauth2/v2/auth')


    def test_profile_completed_required_with_incompleted_profile(self) -> None:
        for username, email, password in PROFILE_COMPLETED_REQUIRED_TEST_CASES:
            with self.subTest(username=username, email=email, password=password):
                try:
                    user = User(
                        username=username,
                        email=email,
                        password=generate_password_hash(password, salt_length=16) if password else None
                    )
                    db.session.add(user)
                    db.session.commit()

                    # INFO: Simulate login
                    with self.client.session_transaction() as session:
                        session['user_id'] = user.id
                        session['username'] = user.username
                        session['email'] = user.email
                        session['oauth_provider'] = user.oauth_provider

                    for route, _ in LOGIN_REQUIRED_TEST_CASES:
                        response = self.get(route)
                        self.check_status_code(response, 302)
                        self.check_route(response, '/profile/complete')

                        response = self.get(route, follow_redirects=True)
                        self.check_status_code(response, 200)
                        self.check_title(response, 'Profile Completion')
                        self.check_flash(response, 'Please complete your profile before proceeding', 'warning')

                except Exception as e:
                    db.session.rollback()
                    raise e

                finally:
                    with self.client.session_transaction() as session:
                        session.clear()
                    db.session.rollback()
                    db.session.delete(user)
                    db.session.commit()


    def test_profile_completed_requriement_with_completed_profile(self) -> None:
        self.login(
            login_type='username_login',
            identifier=self.test_username,
            password=self.test_password
        )
        response = self.get('/profile/complete')
        self.check_status_code(response, 302)
        self.check_route(response, '/profile')

        response = self.get('/profile', follow_redirects=True)
        self.check_status_code(response, 200)
        self.check_title(response, 'Profile')
        self.check_flash(response, 'Profile is already complete', 'info')


    def test_profile_completion_with_valid_data(self) -> None:
       for username, email, password in PROFILE_COMPLETED_REQUIRED_TEST_CASES:
            with self.subTest(username=username, email=email, password=password):
                try:
                    user = User(
                        username=username,
                        email=email,
                        password=generate_password_hash(password, salt_length=16) if password else None
                    )
                    db.session.add(user)
                    db.session.commit()

                    # INFO: Simulate login
                    with self.client.session_transaction() as session:
                        session['user_id'] = user.id
                        session['username'] = user.username
                        session['email'] = user.email
                        session['oauth_provider'] = user.oauth_provider

                    response = self.get('/profile/complete')
                    self.check_status_code(response, 200)
                    self.check_title(response, 'Profile Completion')

                    data = {}
                    if not user.username:
                        data['username'] = self.test_new_username
                    if not user.password:
                        data['password'] = self.test_new_password
                        data['confirmation'] = self.test_new_password

                    response = self.profile_complete(**data)

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
                    db.session.rollback()
                    raise e

                finally:
                    with self.client.session_transaction() as session:
                        session.clear()
                    db.session.rollback()
                    db.session.delete(user)
                    db.session.commit()


    def test_profile_completion_with_invalid_username(self) -> None:
        try:
            user = User(
                username=None,
                email=self.test_new_email,
                password=generate_password_hash(self.test_password, salt_length=16)
            )
            db.session.add(user)
            db.session.commit()

            # INFO: Simulate login
            with self.client.session_transaction() as session:
                session['user_id'] = user.id
                session['username'] = user.username
                session['email'] = user.email
                session['oauth_provider'] = user.oauth_provider

            response = self.get('/profile/complete')
            self.check_status_code(response, 200)
            self.check_title(response, 'Profile Completion')

            for username, expected in INVALID_USERNAME_TEST_CASES:
                with self.subTest(username=username, expected=expected):
                    response = self.profile_complete(username=username)
                    self.check_status_code(response, 200)
                    self.check_title(response, 'Profile Completion')
                    self.check_flash(response, expected, 'warning')

                    self.assertEqual(user.username, None, 'Username exists')
                    self.check_session_exists(user)

        except Exception as e:
            db.session.rollback()
            raise e

        finally:
            with self.client.session_transaction() as session:
                session.clear()
            db.session.rollback()
            db.session.delete(user)
            db.session.commit()


    def test_profile_completion_with_invalid_password(self) -> None:
        try:
            user = User(
                username=self.test_new_username,
                email=self.test_new_email,
                password=None
            )
            db.session.add(user)
            db.session.commit()

            # INFO: Simulate login
            with self.client.session_transaction() as session:
                session['user_id'] = user.id
                session['username'] = user.username
                session['email'] = user.email
                session['oauth_provider'] = user.oauth_provider

            response = self.get('/profile/complete')
            self.check_status_code(response, 200)
            self.check_title(response, 'Profile Completion')

            for password, confirmation, expected in INVALID_PASSWORD_TEST_CASES:
                with self.subTest(password=password, confirmation=confirmation, expected=expected):
                    response = self.profile_complete(password=password, confirmation=confirmation)
                    self.check_status_code(response, 200)
                    self.check_title(response, 'Profile Completion')
                    self.check_flash(response, expected, 'warning')

                    self.assertEqual(user.password, None, 'Password exists')
                    self.check_session_exists(user)

        except Exception as e:
            db.session.rollback()
            raise e

        finally:
            with self.client.session_transaction() as session:
                session.clear()
            db.session.rollback()
            db.session.delete(user)
            db.session.commit()


    # FIXME: THIS TEST CASE IS NOT WORKING
    # def test_google_oauth_callback(self) -> None:
    #     with patch('app.routes.google') as mock_google:
    #         mock_google.return_value.authorize_access_token.return_value = {
    #             'access_token': 'fake-access-token',
    #             'id_token': 'fake-id-token'
    #         }
    #         mock_google.return_value.get.return_value.json.return_value = {
    #             'email': 'here',
    #             'sub': 'here',
    #         }

    #         response = self.get('/authorize/google')
    #         self.check_status_code(response, 302)
    #         self.check_route(response, '/')

    #         user = self.check_user(
    #             username='here',
    #             email='here',
    #             password=None
    #         )
    #         self.check_session(user)

    #         response = self.get('/authorize/google', follow_redirects=True)
    #         self.check_status_code(response, 200)
    #         self.check_title(response, 'Home')
    #         self.check_flash(response, 'Logged in successfully', 'success')


if __name__ == '__main__':
    main()
