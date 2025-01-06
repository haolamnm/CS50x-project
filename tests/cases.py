# INFO: GLOBAL TEST VALUES
TEST_USERNAME = r'username'
TEST_PASSWORD = r'TwFY412nXInZ41nn'
TEST_EMAIL = r'test@gmail.com'

TEST_NEW_USERNAME = r'username2'
TEST_NEW_PASSWORD = r'0Zv8AnzqWUfBo0h1'
TEST_NEW_EMAIL = r'test2@gmail.com'

TEST_INVALID_USERNAME = r'invalid!'
TEST_INVALID_PASSWORD = r'invalid'
TEST_INVALID_EMAIL = r'invalid_email'


# INFO: GLOBAL TEST CASES FOR LOGIN
INVALID_LOGIN_USERNAME_TEST_CASES = { # (username, error)
	(r'', 'Username is required'),
	(r' ', 'Username is required'),
	(r'	', 'Username is required'),
	(TEST_INVALID_USERNAME, 'Invalid credentials'),
} # Number: 4

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
INVALID_USERNAME_TEST_CASES = { # (username, error)
	(r'', 'Username is required'),
	(r' ', 'Username is required'),
	(r' ', 'Username is required'),
	(r'    ', 'Username is required'),
	(r'invalid!', 'Username must be alphanumeric'),
	(r'invalid@', 'Username must be alphanumeric'),
	(r'invalid_', 'Username must be alphanumeric'),
	(r'#invalid', 'Username must be alphanumeric'),
	(r'$invalid', 'Username must be alphanumeric'),
	(r'%invalid', 'Username must be alphanumeric'),
	(r'a', 'Username must be at least 3 characters'),
	(r'aa', 'Username must be at least 3 characters'),
	(r'a' * 101, 'Username is too long'),
	(TEST_USERNAME, 'Username is already taken'),
} # Number: 11

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
	(r'A' * 8, r'A' * 8, 'Password is too weak'),
	(r'@' * 8, r'@' * 8, 'Password is too weak'),
	(r'1' * 8, r'1' * 8, 'Password is too weak'),
	(r'a@' * 8, r'a@' * 8, 'Password is too weak'),
	(r'a1' * 8, r'a1' * 8, 'Password is too weak'),
	(TEST_PASSWORD, TEST_PASSWORD + 'a', 'Password and confirmation do not match'),
} # Number: 13


# INFO: GLOBAL TEST CASES FOR LOGIN REQUIRED
LOGIN_REQUIRED_TEST_CASES = { # (route, status_code)
	('/profile', '302'),
	('/timer', '302'),
	('/logout', '302'),
} # Number: 3


# INFO: GLOBAL TEST CASES FOR PROFILE COMPLETED REQUIRED
INCOMPLETED_PROFILE_TEST_CASES = { # (username, email, password)
	(None, TEST_NEW_EMAIL, None),
	(TEST_NEW_USERNAME, TEST_NEW_EMAIL, None),
	(None, TEST_NEW_EMAIL, TEST_PASSWORD),
} # Number: 3


if __name__ == '__main__':
	pass
