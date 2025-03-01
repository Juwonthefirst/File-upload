from flask import Flask, request, render_template, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from datetime import timedelta
from functools import wraps
from form import LoginForm, SignupForm, FileUpload

# flask configuration settings
app=Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///mock.db"
app.config["SECRET_KEY"] = "c0013adc9440afb24b0e40c0e0d3274c"
app.permanent_session_lifetime = timedelta(days=30)


def login_required(f):
	# wrapper to restrict access to login necessary areas
	@wraps(f)
	def wrapped_function(*args, **kwargs):
		if "username" not in session:
			return redirect(url_for("login"))
		return f(*args, **kwargs)
	return wrapped_function


@app.route("/login")
def login():
	login = LoginForm()
	if login.validate_on_submit 

@app.get("/")
@app.get("/dashboard/")
@login_required
def dashboard():
	pass