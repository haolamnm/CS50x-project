import os
import json
from datetime import datetime, timedelta


MAX_RPM = 10
RPM_LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs', 'RPM.json')


def save_requests_per_minute(data: list[datetime]) -> None:
	"""
	Save the request timestamps to the log file
	E.g. ['2025-01-05 03:10:27.582030', '2025-01-05 03:10:28.582030', ...]

	:param data: The request timestamps
	:return: None
	"""
	with open(RPM_LOG_FILE, 'w') as file:
		json.dump([str(timestamp) for timestamp in data], file, indent=4)


def load_requests_per_minute() -> list[datetime]:
	"""
	Load the request timestamps from the log file

	:return: The request timestamps
	"""
	if not os.path.exists(RPM_LOG_FILE):
		request_timestamps = []
		save_requests_per_minute(request_timestamps)

	with open(RPM_LOG_FILE, 'r') as file:
		request_timestamps = json.load(file)

	return request_timestamps


def reset_requests_per_minute() -> list[datetime]:
	"""
	Load the request timestamps from the log file.
	Reset the request timestamps if the last request was made over a minute ago.

	:return: The request timestamps
	"""
	request_timestamps = load_requests_per_minute()
	current_time = datetime.now()
	request_timestamps = [timestamp for timestamp in request_timestamps if (current_time - datetime.fromisoformat(timestamp)).total_seconds() < 60]
	save_requests_per_minute(request_timestamps)
	return request_timestamps


def can_make_requests_per_minute() -> bool:
	"""
	Check if a request can be made within the minute rate limit

	:return: True if a request can be made, False otherwise
	"""
	request_timestamps = reset_requests_per_minute()

	remaning_requests = MAX_RPM - len(request_timestamps)
	print(f'[INFO] RPM remain: {remaning_requests - 1}/{MAX_RPM}')

	if remaning_requests > 0:
		request_timestamps.append(datetime.now())
		save_requests_per_minute(request_timestamps)
		return True

	wait_time = (request_timestamps[0] + timedelta(minutes=1) - datetime.now()).total_seconds()
	print(f'[INFO] RPM limit reached. Please wait for {wait_time:.2f} seconds.')
	return False


if __name__ == '__main__':
	request_timestamps = reset_requests_per_minute()
	print(f'[INFO] RPM count: {len(request_timestamps)}/{MAX_RPM}')
	print(f'[INFO] Timestamps: {request_timestamps}')
