from flask import Blueprint, render_template
from app.helpers import login_required, profile_completed_required


history = Blueprint('history', __name__)


@history.route('/', methods=['GET'])
@login_required
@profile_completed_required
def index() -> str:
	"""
	This function renders the history page.

	:return: Render the history template.
	"""
	return render_template('history/index.html')
