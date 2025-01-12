from flask import render_template, Blueprint


home = Blueprint('home', __name__)


@home.route('/home', methods=['GET'])
@home.route('/', methods=['GET'])
def index() -> str:
	"""
	The main homepage route

	:return: The homepage template.
	"""
	return render_template('home/index.html')


if __name__ == '__main__':
	pass
