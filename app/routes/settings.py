from flask import Blueprint, render_template
from app.helpers import login_required, profile_completed_required


settings = Blueprint('settings', __name__)


@settings.route('/', methods=['GET'])
@login_required
@profile_completed_required
def index() -> str:
	"""
	This function renders the settings page.

	:return: Render the settings template.
	"""
	return render_template('settings/index.html')
