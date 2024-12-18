from flask import render_template, flash, redirect, url_for, request
from app import app, db


@app.after_request
def after_request(response):
	""""Ensure responses aren't cached"""
	response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
	response.headers['Expires'] = 0
	response.headers['Pragma'] = 'no-cache'
	return response


@app.route('/')
def index():
	"""TODO:"""
	return render_template('index.html')
