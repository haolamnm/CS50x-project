import os
import json
from datetime import datetime


MAX_RPD = 1500
RPD_LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs', 'RPD.json')


def save_requests_per_day(data: dict[str, int]) -> None:
	"""
	Save the daily request count to the log file
	E.g. {'date': '2025-01-01', 'count': 0}

	:param data: The daily request count
	:return: None
	"""
	with open(RPD_LOG_FILE, 'w') as file:
		json.dump(data, file, indent=4)


def load_requests_per_day() -> dict[str, int]:
	"""
	Load the daily request count from the log file

	:return: The daily request count
	"""
	if not os.path.exists(RPD_LOG_FILE):
		data = {'date': str(datetime.now().date()), 'count': 0}
		save_requests_per_day(data)

	with open(RPD_LOG_FILE, 'r') as file:
		data = json.load(file)

	return data


def reset_requests_per_day() -> dict[str, int]:
	"""
	Also load the daily request count from the log file.
	Reset the daily request count if the date has changed.

	:return: The daily request count
	"""
	data = load_requests_per_day()
	current_date = str(datetime.now().date())

	if data['date'] != current_date:
		data = {
			'date': current_date,
			'count': 0
		}
		save_requests_per_day(data)

	return data


def can_make_requests_per_day() -> bool:
	"""
	Check if a request can be made within the daily rate limit

	:return: True if the request can be made, False otherwise
	"""
	data = reset_requests_per_day()

	if data['count'] >= MAX_RPD:
		print(f'[INFO] RPD limit reached. Please wait until tomorrow.')
		return False

	return True


if __name__ == '__main__':
	data = reset_requests_per_day()
	print(f'[INFO] Today date: {data["date"]}')
	print(f'[INFO] RPD count: {data["count"]}/{MAX_RPD}')
