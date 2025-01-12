from flask import Blueprint, render_template
from app.helpers import login_required, profile_completed_required


about = Blueprint('about', __name__)


@about.route('/', methods=['GET'])
@login_required
@profile_completed_required
def index() -> str:
	"""
	This function renders the about page.

	:return: Render the about template.
	"""
	return render_template('about/index.html')
