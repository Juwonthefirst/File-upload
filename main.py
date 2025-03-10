from flask import Flask, request, render_template, redirect, url_for, flash, session, send_file
from werkzeug.utils import secure_filename
from datetime import timedelta
from functools import wraps
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from form import LoginForm, SignupForm, FileUpload
from dotenv import load_dotenv
import os
from MyDBAlchemy import db, Users, Uploads, init_table
from R2_manager import R2
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
			session["next_page"] = request.url
			return redirect(url_for("login"))
		return f(*args, **kwargs)
	return wrapped_function


# routing function
# add username/email login by accepting text then checking if its exists in the username or email database
@app.route("/login", methods = ["GET", "POST"])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		next_page = session.get("next_page")
		session.pop("next_page", "None")
		username = form.username.data
		password = form.password.data
		user_info = db.session.execute(db.select(Users).where(Users.username == username)).scalar_one_or_none()
		if user_info:
			try:
				if ph.verify(user_info.password, password):
					session.permanent = True
					session.update({
											"id" : user_info.id,
											"username" : username, 
											"email" : user_info.email 
											})
					return redirect( next_page or url_for("home"))
			except VerifyMismatchError:
				flash("incorrect username and password combination")
		else:
			flash("incorrect username and password combination")			
	return render_template("login.html", form=form)


@app.route("/signup", methods = ["GET", "POST"])
def signup():
	form = SignupForm()
	if form.validate_on_submit():
		next_page = session.get("next_page")
		session.pop("next_page", "None")
		username = form.username.data
		email = form.email.data
		password = form.password.data
		username_exist = Users.fetch("username", username)
		email_exist = Users.fetch("email", email)
		if (not username_exist) and (not email_exist):
			hashed_password = ph.hash(password)
			new_user = Users(username = username, email = email, password = hashed_password)
			if not new_user.save():
				form.username.errors.append("Unknown error, Try logging in")
			else:
				session.permanent = True
				session.update({
												"id" : new_user.id,
												"username" : username, 
												"email" : email 
												})
				return redirect(next_page or url_for("home"))
		else:
			if username_exist: 
			    form.username.errors.append("Username already in use")
			if email_exist: 
			    form.email.errors.append("Email already in use")
	return render_template("signup.html",  form=form)
	

@app.get("/")
@login_required
def home():
	user_id = session.get("id")												
	folders = Uploads.fetch("folder", user_id, search = "user_id", all = True)
	return render_template("home.html", folders = list(dict.fromkeys(folders)))
	

@app.get("/cloud/<string:folder>")
@login_required
def cloud(folder):
	user_id = session.get("id")
	files = Uploads.fetch("filename", folder, search = "folder", all = True)
	return render_template("home.html", files=files)
	

@app.get("/cloud/<string:folder>/<string:filename>/download")
@login_required
def download(folder, filename):
	
	stored_file = db.session.execute(
	db.select(Uploads.filelocation).where(and_(Uploads.folder == folder, Uploads.filename == filename))
	).scalar_one()
	
	response = R2.get_file(stored_file)
	return send_file (
		BytesIo(file_data),
		download_name = filename,
		as_attachment = True
		)



@app.route("/upload", methods = ["GET", "POST"])
@login_required
def upload():
	user_id = session["id"]
	username = session["username"]
	upload = FileUpload()
	if upload.validate_on_submit():
		file = upload.file.data
		file_name = secure_filename(file.filename)
		file_size = len(file.read())
		file.seek(0)
		file_data = Uploads(filename = file_name, filesize = file_size, filelocation = "nill", user_id = user_id)
		file_data.save()
		file_location = f"{username}/{folder}/{file_data.id}"
		file_data.filelocation = file_location
		if R2.upload(file, file_location):
			flash("Cloud upload successful", "success")
		else:
			flash("Something went wrong, try again later", "error")
	return render_template("home.html", upload = upload)

@app.get("/session")
@login_required
def sessions():
	return dict(session)
	
@app.route("/logout")
@login_required
def logout():
	session.clear()
	return redirect(url_for("login"))	
app.run(debug = True)