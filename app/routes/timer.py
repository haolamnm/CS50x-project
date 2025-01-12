from flask import Blueprint, render_template
from app.helpers import login_required, profile_completed_required


timer = Blueprint('timer', __name__)


@timer.route('/', methods=['GET'])
@login_required
@profile_completed_required
def index() -> str:
	"""
	This function renders the timer page.

	:return: Render the timer template.
	"""
	return render_template('timer/index.html')
