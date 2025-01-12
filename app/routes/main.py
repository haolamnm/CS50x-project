from flask import Blueprint


main = Blueprint('main', __name__)


@main.after_request
def after_request(response: object) -> object:
	""""
	This function ensures responses aren't cached.

	:param response: The response object.
	:return: The response object.
	"""
	response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
	response.headers['Expires'] = 0
	response.headers['Pragma'] = 'no-cache'
	return response


if __name__ == '__main__':
	pass
