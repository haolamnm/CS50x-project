import sys
from app import create_app
from config import Config, DevelopmentConfig


def main():
	if len(sys.argv) != 2:
		print('Usage: python run.py [mode]')
		return

	mode = sys.argv[1]
	if mode == 'development':
		app = create_app(DevelopmentConfig)
		app.run(debug=True)
	elif mode == 'production':
		app = create_app(Config)
		app.run()
	else:
		print('Available modes: development, production')


if __name__ == '__main__':
	main()
