from flask import Flask, request, render_template, redirect, url_for, flash, session, send_file
from werkzeug.utils import secure_filename
from datetime import timedelta, datetime
from functools import wraps
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from form import LoginForm, SignupForm, FileUpload
from dotenv import load_dotenv
import os
from MyDBAlchemy import db, Users, Uploads, Errors, init_table
from sqlalchemy import and_, or_
from R2_manager import R2
from io import BytesIO
import jwt
from flask_caching import Cache


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
jwt_key = os.getenv("SECRET_KEY")

#initializing other modules
db.init_app(app)
init_table(app)
ph = PasswordHasher()
cache = Cache(app, config = {"CACHE_TYPE" : "simple"})


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
	try:
		next_page = session.get("next_page")
		if "id" in session:
			return redirect(url_for("home"))
		form = LoginForm()
		if form.validate_on_submit():
			username = form.username.data.capitalize().strip()
			password = form.password.data.strip()
			user_info = db.session.execute(db.select(Users).where(or_(Users.username == username, Users.email == username))).scalar_one_or_none()
			if user_info:
				try:
					if ph.verify(user_info.password, password):
						session.pop("next_page", "None")
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
	except Exception as err:
		Errors(error = err).log()			
	return render_template("login.html", form=form)


@app.route("/signup", methods = ["GET", "POST"])
def signup():
	form = SignupForm()
	if "id" in session:
		return redirect(url_for("home"))
	if form.validate_on_submit():
		next_page = session.get("next_page")
		session.pop("next_page", "None")
		username = form.username.data.strip().capitalize()
		email = form.email.data.strip().lower()
		password = form.password.data.strip()
		username_exist = Users.fetch("username", username)
		email_exist = Users.fetch("email", email)
		if (not username_exist) and (not email_exist):
			hashed_password = ph.hash(password)
			new_user = Users(username = username, email = email, password = hashed_password)
			try:
				if not new_user.save():
					form.username.errors.append("Unknown error, Try logging in")
				else:
					session.permanent = True
					session.update({
													"id" : new_user.id,
													"username" : username, 
													"email" : email 
													})
					#if not cache.get("sign up"):
					return redirect(next_page or url_for("home"))
			except Exception as err:
				Errors(error = err).log()
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
	
# route for downloading files
@app.get("/cloud/<string:folder>/<string:filename>/download")
@login_required
def download(folder, filename, user_id = None):
	if not user_id:
		user_id = session.get("id")
	stored_file = db.session.execute(
		db.select(Uploads.filelocation).where(
			and_(
					Uploads.folder == folder, 
					Uploads.filename == filename,
					Uploads.user_id == user_id
					)
				) 
			).scalar_one_or_none()
	
	
	try:
		response = R2.get_file(stored_file)
	except Exception as err:
		Errors(error = err, user_id = session.get("id")).log()
		response = None
		flash("Something went wrong, please try again later")
		
	if not response:
		flash("File not found")
		return redirect(url_for("cloud", folder = folder))
	return send_file (
		BytesIO(response),
		download_name = filename,
		as_attachment = True
		)


@app.get("/cloud/<string:folder>/<string:filename>/share")
@login_required
def share(folder, filename):
	user_id = session.get("id")
	share_link = " "
	if form.validate_on_submit():
		token = jwt.encode(
			{
				"folder" : folder, 
				"filename" : filename, 
				"sender_id" : user_id, 
				"recipient_id":  recievers,
				"exp" : datetime.utcnow() + timedelta(hours = 1) 
			},
			 jwt_key,
			 algorithm = "HS256"
		)
		share_link = url_for("shared", token = token)
	return render_template("cloud_share.html", link = share_link)


@app.get("/shared/<token>")
@login_required
def shared(token):
	user_id = session.get("id")
	try:
		file_data = jwt.decode(token, jwt_key, algorithm = "HS256")
	except jwt.ExpiredSignatureError:
		return render_template("Shared.html", error = "Expired Link")
	except jwt.InvalidTokenError:
		return render_template("Shared.html", error = "Invalid Link")
	except Exception as err:
		Errors(error = err, user_id = session.get("id")).log()
		
	if (user_id in file_data.get("recipient_id")) or (not file_data.get("recipient_id")):
		folder = file_data.get("folder")
		filename = file_data.get("filename")
		sender_id = file_data.get("sender_id")
		return download(folder, filename, user_id = sender_id)
	else:
		return render_template("Shared.html", error = "Access Denied")
	

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
		try:
			if R2.upload(file, file_location):
				flash("Cloud upload successful", "success")
			else:
				flash("Unable to connect to the cloud", "error")
		except Exception as err:
			Errors(error = err, user_id = user_id).log()
			flash("Something went wrong, please try again later", "error")
			
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

""" 
Forms to create
1. Profile
2. Cloud share(send)
3. Upload area
4. Cloud share(recieve)
 
Forms to rework (reason)
1.Signup form (
							to allow for better login experience, like
							email verification
							space for full name
							multi page signup
							
							)
2. LoginForm(
							add remember me field
							allow login with username or email
						)
						
	
Rework filename to be safe for web and urls instead of filesystem
"""#