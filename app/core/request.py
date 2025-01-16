import os
import google.generativeai as genai
from dotenv import load_dotenv
from app.core.rpd import *
from app.core.rpm import *


load_dotenv()


PROMPT_TEMPLATE_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs', 'prompt.txt')
RESPONSE_LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs', 'response.json')
MAX_REASON_LENGTH = 600
EMPTY_REASON = '<<EMPTY REASON>>'

genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))

model = genai.GenerativeModel(
	model_name='gemini-2.0-flash-exp'
)


def create_prompt(reason: str) -> str:
	"""
	Create a prompt based on the given reason

	:param reason: The reason for the request
	:return: The generated prompt
	"""
	with open(PROMPT_TEMPLATE_FILE, 'r') as file:
		prompt = file.read()

	prompt = prompt.replace(EMPTY_REASON, reason)

	return prompt


def make_request(prompt: str) -> str | None:
	"""
	Call the model API with the given prompt

	:param prompt: The prompt to generate content
	:return: The generated content
	"""
	if not can_make_requests_per_day():
		return None

	if not can_make_requests_per_minute():
		return None

	try:
		response = model.generate_content(prompt)

		# Update the daily request count
		data = reset_requests_per_day()
		data['count'] += 1
		save_requests_per_day(data)

		return response.text

	except Exception as e:
		print(f'[ERROR] {e}')
		return None


def main() -> None:
	reason = "Hello!"

	if len(reason) > MAX_REASON_LENGTH:
		print(f'[ERROR] Reason is too long. Max length is {MAX_REASON_LENGTH}')
		return

	prompt = create_prompt(reason=reason)

	raw_response = make_request(prompt=prompt)

	response = raw_response.strip().replace('json\n', '').strip().replace('```', '')

	try:
		cleaned_response = json.loads(response)
		with open(RESPONSE_LOG_FILE, 'w') as file:
			json.dump(cleaned_response, file, indent=4)

	except json.JSONDecodeError as e:
		print(f'[ERROR] {e}')


if __name__ == '__main__':
	main()
