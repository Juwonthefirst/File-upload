from flask import Flask, request, render_template, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from datetime import timedelta
from functools import wraps
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from form import LoginForm, SignupForm, FileUpload
from dotenv import load_dotenv
import os
from MyDBAlchemy import db, Users, Uploads, init_table

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
init_table(app)
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
	error_dict = {}
	form = LoginForm()
	if form.validate_on_submit():
		username = form.username.data
		password = form.password.data
		user_info = db.session.execute(db.select(Users).where(Users.username == username)).scalar_one_or_none()
		if user_info:
			try:
				if ph.verify(user_info.password, password):
					session["username"] = username
					session["id"] = user_info.id
					return redirect(url_for("dashboard"))
			except VerifyMismatchError:
				error_dict["password_error"] = True
		else:
			error_dict["user_error"] = True			
	return render_template("login.html", form=form, error=error_dict)


@app.route("/signup", methods = ["GET", "POST"])
def signup():
	form = SignupForm()
	if form.validate_on_submit():
		username = form.username.data
		email = form.email.data
		password = form.password.data
		username_exist = Users.Fetch("username", username)
		email_exist = Users.Fetch("email", email)
		if (not username_exist) and (not email_exist):
			hashed_password = ph.hash(password)
			new_user = Users(username = username, email = email, password = hashed_password)
			new_user.save()
			session["username"] = username
			session["id"] = new_user.id
			return redirect(url_for("dashboard"))
		else:
			potential_error = [username_exist, email_exist]
			errors = [error for error in potential_error if error]
	return render_template("signup.html", errors = errors,  form=form)
	
					
@app.get("/dashboard/")
@app.get("/")
@login_required
def dashboard():
	return render_templatr("home.html")
	
app.run(debug=True)