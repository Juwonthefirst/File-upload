from flask import Flask, request, render_template, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from datetime import timedelta
from functools import wraps
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from form import LoginForm, SignupForm, FileUpload
from dotenv import load_dotenv
import os
from MyDBAlchemy import db, Users, Fetch_user, create_table

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


#initializing other modules
db.init_app(app)
create_table()
ph = PasswordHasher()


# wrapper to restrict access to login necessary areas
def login_required(f):
	@wraps(f)
	def wrapped_function(*args, **kwargs):
		if "username" not in session:
			return redirect(url_for("login"))
		return f(*args, **kwargs)
	return wrapped_function


# routing function

@app.route("/login", methods = ["GET", "POST"])
def login():
	LoginForm = LoginForm()
	if LoginForm.validate_on_submit():
		# sql authorization here before redirecting
		session["username"] = LoginForm.username.data
		return redirect(url_for("dashboard"))
	return render_template("login.html", form=LoginForm)


@app.route("/signup", methods = ["GET", "POST"])
def signup():
	SignupForm = SignupForm()
	if SignupForm.validate_on_submit():
		username = SignupForm.username.data
		email = SignupForm.email.data
		passw = SignupForm.password.data
		username_exist = Fetch_user("username", username)
		email_exist = Fetch_user("email", email)
		if (not username_exist) and (not email_exist):
			hashed_password = ph.hash(passw)
			Users(username = username, email = email, password = hashed_password)
			#sql authorization before redirecting
			session["username"] = username
			return redirect(url_for("dashboard"))
	return render_template("signup.html", form=SignupForm)
	
					
@app.get("/dashboard/")
@app.get("/")
@login_required
def dashboard():
	return render_template("home.html")