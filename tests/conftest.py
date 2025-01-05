import os
import pytest


@pytest.fixture(autouse=True)
def cleanup_session_files():
    """
    Clean up session files before and after each test.

    :return: None
    """
    session_dir = os.path.join(os.getcwd(), 'flask_session')

    existing_files = set()
    if os.path.exists(session_dir):
        existing_files = set(os.listdir(session_dir))

    yield

    if os.path.exists(session_dir):
        current_files = set(os.listdir(session_dir))
        new_files = current_files - existing_files

        for file in new_files:
            file_path = os.path.join(session_dir, file)
            if os.path.exists(file_path):
                os.remove(file_path)
