from flask import Flask, request, render_template, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from datetime import timedelta
from functools import wraps
from form import LoginForm, SignupForm, FileUpload
from dotenv import load_dotenv
import os

# loading and validating variables
load_dotenv(".env")

def validate_env():
	variables = ["SECRET_KEY", "DATABASE_URL"]
	for var in variables:
		if not os.getenv(var):
			raise RuntimeError(f"{var} is not set, check your enviroment variable")
			

# flask configuration settings
app=Flask(__name__)
validate_env()
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.permanent_session_lifetime = timedelta(days=1)


# wrapper to restrict access to login necessary areas
def login_required(f):
	@wraps(f)
	def wrapped_function(*args, **kwargs):
		if "username" not in session:
			return redirect(url_for("login"))
		return f(*args, **kwargs)
	return wrapped_function


# routing function

@app.route("/login")
def login():
	login = LoginForm()
	if login.validate_on_submit():
		
@app.get("/dashboard/")
@app.get("/")
@login_required
def dashboard():
	pass