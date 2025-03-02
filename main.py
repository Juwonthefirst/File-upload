from flask import Flask, request, render_template, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from datetime import timedelta
from functools import wraps
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from form import LoginForm, SignupForm, FileUpload
from dotenv import load_dotenv
import os
from MyDBAlchemy import db, Users,  create_table
import ssl

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

ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.permanent_session_lifetime = timedelta(days=1)
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {"connect_args": {"ssl_context": ssl_context}}

#initializing other modules
db.init_app(app)
create_table(app)
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
		username_exist = Users.Fetch("username", username)
		email_exist = Users.Fetch("email", email)
		if (not username_exist) and (not email_exist):
			hashed_password = ph.hash(passw)
			new_user = Users(username = username, email = email, password = hashed_password)
			new_user.save()
			session["username"] = username
			return redirect(url_for("dashboard"))
		else:
			potential_error = [username_exist, email_exist]
			errors = [error for error in potential_error if error]
	return render_template("signup.html", errors = errors,  form=SignupForm)
	
					
@app.get("/dashboard/")
@app.get("/")
@login_required
def dashboard():
	return render_templatr("home.html")