# INFO: GLOBAL TEST VALUES
TEST_PASSWORD = r'TwFY412nXInZ41nn'
TEST_EMAIL = r'test@gmail.com'

TEST_NEW_PASSWORD = r'0Zv8AnzqWUfBo0h1'
TEST_NEW_EMAIL = r'test2@gmail.com'

TEST_INVALID_PASSWORD = r'invalid'
TEST_INVALID_EMAIL = r'invalid_email'


# INFO: GLOBAL TEST CASES FOR LOGIN
INVALID_LOGIN_EMAIL_TEST_CASES = { # (email, error)
	(r'', 'Email is required'),
	(r' ', 'Email is required'),
	(r'	', 'Email is required'),
	(TEST_INVALID_EMAIL, 'Invalid credentials'),
} # Number: 4

INVALID_LOGIN_PASSWORD_TEST_CASES = { # (password, error)
	(r'', 'Password is required'),
	(TEST_INVALID_PASSWORD, 'Invalid credentials'),
} # Number: 2


# INFO: GLOBAL TEST CASES FOR REGISTER
INVALID_EMAIL_TEST_CASES = { # (email, error)
	(r'', 'Email is required'),
	(r' ', 'Email is required'),
	(r'	', 'Email is required'),
	(r'invalid', 'Email is invalid'),
	(r'invalid@', 'Email is invalid'),
	(r'invalid@invalid', 'Email is invalid'),
	(r'invalid@invalid.', 'Email is invalid'),
	(r'invalid@invalid.c', 'Email is invalid'),
	(r'invalid@@gmail.com', 'Email is invalid'),
	(r'invalid@gmail..com', 'Email is invalid'),
	(r'a' * 101 + '@gmail.com', 'Email is too long'),
	(TEST_EMAIL, 'Email is already taken'),
} # Number: 12

INVALID_PASSWORD_TEST_CASES = { # (password, confirmation, error)
	(r'', r'a', 'Password is required'),
	(r'a', r'', 'Confirmation is required'),
	(r'', r'', 'Password is required'),
	(r'a', r'a', 'Password must be at least 8 characters'),
	(r' ', r' ', 'Password must be at least 8 characters'),
	(r'	', r'	', 'Password must be at least 8 characters'),
	(r'a' * 8, r'a' * 8, 'Password is too weak'),
	(TEST_PASSWORD, TEST_PASSWORD + 'a', 'Password and confirmation do not match'),
} # Number: 13


# INFO: GLOBAL TEST CASES FOR LOGIN REQUIRED
LOGIN_REQUIRED_TEST_CASES = { # (route, status_code)
	('/profile/', 302)
} # Number: 3


if __name__ == '__main__':
	pass
