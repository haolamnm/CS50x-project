from unittest import main
from pytest import mark
from tests.bases import TestRouteBase


pytestmark = mark.filterwarnings('ignore::DeprecationWarning')


class TestRouteError(TestRouteBase):
    """
    Test the handling of error routes
    """

    def test_page_not_found(self) -> None:
        """
        Try to access an invalid page then check the response

        :return: None
        """
        response = self.get('/invalid_page')
        self.check_status_code(response, 404)

        response = self.get('/invalid_page', follow_redirects=True)
        # self.check_title(response, '404 Not Found')
        self.check_flash(response, 'Page not found', 'danger')
        self.check_session_absent()


if __name__ == '__main__':
    main()
