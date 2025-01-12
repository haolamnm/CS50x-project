from flask import Blueprint, render_template
from app.helpers import login_required, profile_completed_required


insights = Blueprint('insights', __name__)


@insights.route('/', methods=['GET'])
@login_required
@profile_completed_required
def index() -> str:
	"""
	This function renders the insights page.

	:return: Render the insights template.
	"""
	return render_template('insights/index.html')
