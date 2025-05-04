from flask import Flask, request, render_template, redirect, url_for, flash, session, send_file
from redis import Redis, exceptions, ConnectionPool, SSLConnection
from datetime import timedelta, datetime, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from form import (
									LoginForm, SignupPage1, 
									SignupPage2, SignupPage3,
									FileUpload, FileShare, 
									SharedFileDownload, 
									ChangeFirstname,
									ChangeLastname,
									ChangeEmail, RequestChangePass,
									ChangePass, RequestOTP,
									VerifyPassword, ConfirmDelete		
									)
from MyDBAlchemy import db, Users, Uploads, Errors, init_table
from helper_functions import (
														login_required,
														get_mime,
														validate_mime, 
														send_mail, 
														verify_otp, 
														not_logged_in, 
														resend_mail,
														stringify_byte,
														stringify_time,
														add_extension,
														enable_cookies
													)
from R2_manager import R2Manager as R2
from io import BytesIO
from werkzeug.utils import secure_filename
import secrets, os, logging

# flask configuration settings
app = Flask(__name__)
app.config.from_pyfile("config.py")
app.permanent_session_lifetime = timedelta(days = 30)

#initializing other modules
db.init_app(app)
init_table(app)
ph = PasswordHasher()
logging.basicConfig(level = logging.ERROR, format = "%(asctime)s - %(levelname)s - %(message)s")
redis_pool = ConnectionPool(
							host = os.getenv("REDIS_HOST"),
							password = os.getenv("REDIS_PASS"),
							port = 6379,
							connection_class = SSLConnection,
							max_connections = 10
							)
cache = Redis(connection_pool = redis_pool)

# routing function
#give the shared template's file details a max height with overflow-y auto '
@app.route("/login/", methods = ["GET", "POST"])
@not_logged_in
def login():
	form = LoginForm()
	login_template = render_template("login.html", form = form)
	try:
		anonymous_user_id = request.cookies.get("anonymous_user_id")	
		next_page = session.get("next_page")
		if form.validate_on_submit():
			detail = form.username.data.capitalize().strip()
			password = form.password.data.strip()
			user_info = Users.fetch_user_row(detail)
			
			if not user_info:
				flash("Incorrect Username and Password combination", "error")
				return login_template
				
			if cache.exists(f"{user_info.id}: locked"):
				time_until_unlocked = cache.ttl(f"{user_info.id}: locked")						
				flash(f"Your account has been locked for {stringify_time(time_until_unlocked)}", "error")
				return login_template
				
			ph.verify(user_info.password, password)
			file_sizes = Uploads.fetch("filesize", user_info.id, search = "user_id", all = True)
			session.clear()
			session.permanent = True
			session.update({
											"id": user_info.id,
											"username": user_info.username,
											"total_file_size": sum(file_sizes)
										})
			cache.delete(f"{anonymous_user_id} : {user_info.id} attempts")
			return redirect( next_page or url_for("home"))
				
	except VerifyMismatchError:
		key = f"{anonymous_user_id} : {user_info.id} attempts"
		no_of_attempts = cache.incrby(key, 1)
		cache.expire(key, 60 * 10)
		flash(f"Incorrect Username and Password combination, {5 - no_of_attempts} attempts left", "error")
		if no_of_attempts == 5:
			cache.delete(key)
			cache.set(f"{user_info.id}: locked", "locked", ex = 60 * 30)
						
	except Exception as err:
		response = Errors(error = str(err)).log()
		logging.error(response)
		flash("Something went wrong, try again later", "error")
		
	return login_template


@app.route("/signup/user-info/", methods = ["GET", "POST"])
@not_logged_in
def signup1():
				
	form = SignupPage1()
	
	if form.validate_on_submit():
		first_name = form.first_name.data.strip().capitalize()
		last_name = form.last_name.data.strip().capitalize()
		email = form.email.data.strip().capitalize()
		email_exist = Users.fetch("email", email)
		if email_exist:
			form.email.errors.append("Email already in use")
			return render_template("signup(page_1).html",  form = form)
			
		session.permanent = True
		session.update({
										"first_name": first_name,
										"last_name": last_name,
										"email": email											
									})
		response = send_mail(app, email)
		if response == "Email sent":
			return redirect(url_for("signup2"))
		flash("Something went wrong, try again later", "error")
		response = Errors(error = str(response)).log()
		logging.error(response)
		
	return render_template("signup(page_1).html",  form = form)
				
			
@app.route("/signup/verify/", methods = ["GET", "POST"])
@not_logged_in
def signup2():
	
	if "email" not in session:
		return redirect(url_for("signup1"))
	
	request_otp = RequestOTP()
	form = SignupPage2()
	if form.validate_on_submit():
		otp = form.otp.data
		response = verify_otp(otp)
		match (response):
			case "verified":
				session["email_verified"] = True
				return redirect(url_for("signup3"))
			case "incorrect":
				flash("Incorrect OTP, check and try again later", "error")
			case "invalid":
				flash("Invalid OTP, request a new one", "error")
			case _:
				flash("Something went wrong, try again later", "error")
				status = Errors(error = str(response)).log()
				logging.error(status)
				
	elif request_otp.validate_on_submit():
		response = resend_mail(app, session.get("email"))
		if isinstance(response, int):
			flash(f"Wait {response} before requesting for a new otp")
		else:
			response = Errors(error = str(response)).log()
			logging.error(response)
		
	return render_template("signup(page_2).html",  form = form, request = request_otp, title = "Stratovault - verify OTP")

@app.route("/signup/finish/", methods = ["GET", "POST"])
@not_logged_in
def signup3():
		
	if "email_verified" not in session:
		return redirect(url_for("signup2"))
		
	form = SignupPage3()
	
	if form.validate_on_submit():
		next_page = session.get("next_page")
		username = form.username.data.strip().capitalize()
		password = form.password.data.strip()
		username_exist = Users.fetch("username", username)
		if username_exist:
			form.username.errors.append("Username already in use")
			return render_template("signup(page_3).html",  form = form)
			
		hashed_password = ph.hash(password)
		new_user = Users(
											username = username,
											firstname = session.get("first_name"), 
											lastname = session.get("last_name"), 
											email = session.get("email"),
											password = hashed_password
										)
		try:
			if not new_user.save():
				flash("Unknown error, Try logging in", "flash")
				return render_template("signup(page_3).html",  form = form)
			session.clear()
			session.permanent = True
			session.update({
											"id" : new_user.id,
											"username" : username, 
											"total_file_size": 0
										})
			return redirect(next_page or url_for("home"))
			
		except Exception as err:
			response = Errors(error = str(err)).log()
			logging.error(response)
			flash("Something went wrong, please try again", "error")
			
	return render_template("signup(page_3).html",  form = form)
	

@app.get("/")
@login_required
def home():
	user_id = session.get("id")
	
	if Users.fetch("has_profile_picture", user_id, search = "id"):
		profile_picture = R2.preview(f"profile_pictures/{user_id}", expiration = 30)
	else:
		profile_picture= url_for("static", filename = "image/logo.webp")					
							
	folders = Uploads.fetch("folder", user_id, search = "user_id", all = True)
	return render_template(
												"home.html", 
												folders = list(dict.fromkeys(folders)), 
												heading = "Stratovault", 
												profile_picture = profile_picture
											)
	

@app.get("/cloud/<string:folder>/")
@login_required
def cloud(folder):
	user_id = session.get("id")
	
	if Users.fetch("has_profile_picture", user_id, search = "id"):
		profile_picture = R2.preview(f"profile_pictures/{user_id}", expiration = 30)
	else:
		profile_picture= url_for("static", filename = "image/logo.webp")
		
	files = Uploads.fetch_filename(user_id, folder, all = True)
	if not files: 
		flash("Folder doesn't exist")
		return redirect(url_for("home"))
	return render_template(
												"home.html", 
												files = list(dict.fromkeys(files)), 
												heading = folder, 
												folder = folder,
												profile_picture = profile_picture
											)
	
# route for downloading files
@app.get("/cloud/<string:folder>/<string:filename>/download/")
@login_required
def download(folder, filename):
	user_id = session.get("id")
	file_row = Uploads.fetch_filerow(user_id, folder, filename)
	if not file_row:
		flash("File not found", "error")
		return redirect(url_for('cloud', folder = folder))
	file_location = file_row.filelocation
	try:
		file = R2.get_file(file_location)
	except Exception as err:
		response = Errors(error = str(err), user_id = session.get("id")).log()
		logging.error(response)
		flash("Something went wrong, please try again later", "error")
		return redirect(url_for("cloud", folder = folder))
		
	if  file == "File not found":
		flash("File not found", "error")
		return redirect(url_for("cloud", folder = folder))
		
	return send_file (
									BytesIO(file),
									download_name = filename,
									as_attachment = True
								)
	
	
@app.route("/cloud/<string:folder>/<string:filename>/delete/", methods = ["GET", "POST"])
@login_required
def delete(folder, filename):
	user_id = session.get("id")
	form = ConfirmDelete()
	if form.validate_on_submit():
		file_row = Uploads.fetch_filerow(user_id, folder, filename)
		if not file_row:
			flash("File not found", "error")
			return redirect(url_for('cloud', folder = folder))
		file_location = file_row.filelocation
		try:
			if R2.delete(file_location):
				file_row.delete()
				session["total_file_size"] -= file_row.filesize
				flash(f"{filename} removed from your cloud", "success")
			else:
				flash("Unable to connect to your cloud", "error")
					
		except Exception as err:
			response = Errors(error = str(err), user_id = user_id).log()
			logging.error(response)
			flash("Unable to connect to your cloud", "error")
			
		return redirect(url_for("cloud", folder = folder))
		
	return render_template("confirm.html", form = form, filename = filename)
	
	
@app.get("/cloud/<string:folder>/<string:filename>/preview/")
@login_required
def preview(folder, filename):
	user_id = session.get("id")
	try:
		allowed_mime = ["image", "video", "audio"]
		user_id = session.get("id")
		file_row = Uploads.fetch_filerow(user_id, folder, filename)
		if not file_row:
			flash("File not found", "error")
			return redirect(url_for('cloud', folder = folder))
		file_type = file_row.content_type
		file_location = file_row.filelocation
		for mime in allowed_mime:
			if file_type.startswith(mime):
				url = R2.preview(file_location)
				if not url:
					flash("Unable to connect to your cloud", "error")
					return redirect(url_for("cloud", folder = folder))
					
				return render_template ("preview.html", type = mime,url = url)
		flash("Can only preview Images, Videos or Audio", "error")
	except Exception as err:
		response = Errors(error = str(err), user_id = user_id).log()
		logging.error(response)
		flash("Something went wrong, try again later", "error")
	
	return redirect(url_for("cloud", folder = folder))	
	
@app.route("/cloud/<string:folder>/<string:filename>/share/", methods = ["GET", "POST"])
@login_required
def share(folder, filename):
	user_id = session.get("id")
	user_firstname = db.session.get(Users, user_id).firstname
	file_row = Uploads.fetch_filerow(user_id, folder, filename)
	if not file_row:
		flash("File not found", "error")
		return redirect(url_for("cloud", folder = folder))
	form = FileShare()
	share_link = "Click SHARE to get your file link"
	if form.validate_on_submit():
		raw_recievers = form.receiver.data
		recievers = list(map( lambda x: x.strip().capitalize(), raw_recievers.split(",")))
		previewable_mime = ["image/jpeg", "image/png", "image/gif", "image/webp",  "video/mp4", "video/quicktime", "video/x-msvideo","video/x-matroska", "audio/mpeg", "audio/wav", "audio/ogg"]
		if file_row.content_type in previewable_mime:
			url = R2.preview(file_row.filelocation)
		else:
			url = "Not previewable"
		try:
			token = secrets.token_hex(4)
			cache.hset(token, mapping = {
																	"sender_name": user_firstname,
																	"filename": file_row.filename,
																	"filelocation": file_row.filelocation,
																	"filesize": stringify_byte(file_row.filesize),
																	"filetype": file_row.content_type,
																	"url": url,
																	"receivers": ",".join(recievers)
																}
												)
			cache.expire(token, 3600)
			share_link = url_for("shared", token = token, _external = True)
		except exceptions.ConnectionError:
			flash("Unable to generate link at the moment", "error")
	return render_template(
												"cloud_share.html", 
												link = share_link, 
												filename = file_row.filename, 
												filesize = stringify_byte(file_row.filesize), 
												form = form
											)


@app.route("/shared/<token>/", methods = ["GET", "POST"])
@enable_cookies
def shared(token):
	user_id = session.get("id")
	username = session.get("username")
	form = SharedFileDownload()
	if form.validate_on_submit():
		try:
			file_location = cache.hget(token, "filelocation").decode()
			file_name = cache.hget(token, "filename").decode()
			response = R2.get_file(file_location)
		except Exception as err:
			logging.error(Errors(error = str(err), user_id = user_id).log())
			response = None
			flash("Something went wrong, please try again later", "error")
			
		if response and response != "File not found":
			return send_file(
											BytesIO(response),
											download_name = file_name,
											as_attachment = True
										)
									
		elif not response:
			flash("Unable to connect to sender's cloud", "error")
				
		elif response == "File not found":
			flash("File not found", "error")
			
		sender_name = cache.hget(token, "sender_name").decode()
		url = cache.hget(token, "url").decode()
		return render_template(
													"shared.html",
													filename = file_name, 
													filesize = cache.hget(token, "filesize").decode(), 
													filetype = cache.hget(token, "filetype").decode(), 
													sender = sender_name, 
													url = url, 
													form = form
												)
									
	try:
		if not cache.exists(token):
			return render_template("shared.html", error = "Invalid Link")
				
		receivers_list = cache.hget(token, "receivers").decode()
		if username in receivers_list.split(",") or receivers_list == "All":
			sender_name = cache.hget(token, "sender_name").decode()
			file_size = cache.hget(token, "filesize").decode()
			file_type = cache.hget(token, "filetype").decode()
			file_name = cache.hget(token, "filename").decode()
			file_location = cache.hget(token, "filelocation").decode()
			url = cache.hget(token, "url").decode()
			
			return render_template(
														"shared.html",
														filename = file_name, 
														filesize = file_size, 
														filetype = file_type, 
														sender = sender_name, 
														url = url, 
														form = form
													)
													
	except exceptions.ConnectionError:
		flash("Unable to retrieve data at the moment", "error")
	except Exception as err:
		response = Errors(error = str(err), user_id = user_id).log()
		logging.error(response)
		flash("Something went wrong, try again later", "error")										
	return render_template("shared.html", error = "Access Denied")


@app.route("/password/change/request/", methods = ["GET", "POST"])
@enable_cookies
def request_password_change():
	form = RequestChangePass()
	RequestChangePass_template = render_template("request_password_change.html", form = form)
	
	if form.validate_on_submit():
		detail = form.detail.data.strip().capitalize()
		user_info = Users.fetch_user_row(detail)
		if not user_info:
			flash("User doesn't exist", "error")
			return RequestChangePass_template
		response = send_mail(app, user_info.email)
		if response != "Email sent":
			status = Errors(error = str(response)).log()
			logging.error(status)
			flash("Something went wrong, try again later", "error")
			return RequestChangePass_template
			
		session["recovery_id"] = user_info.id
		session["recovery_email"] = user_info.email
		return redirect(url_for("change_password"))
	return RequestChangePass_template

@app.route("/password/change/", methods = ["GET", "POST"])
@enable_cookies
def change_password():
	user_id = session.get("recovery_id")
	form = ChangePass()
	request_otp = RequestOTP()
	if "recovery_email" not in session:
		return redirect(url_for("request_password_change"))
	if form.validate_on_submit():
		otp = form.otp.data
		response = verify_otp(otp)
		match (response):
			case "verified":
				password = form.password.data
				hashed_password = ph.hash(password)
				Users.update_pass(user_id, hashed_password)
				session.clear()
				flash("Password change successful", "success")
				return redirect(url_for("login"))
			case "incorrect":
				flash("Incorrect OTP, check and try again later", "error")
			case "invalid":
				flash("Invalid OTP, request a new one", "error")
			case _:
				flash("Something went wrong, try again later", "error")
				response = Errors(error = str(response)).log()
				logging.error(response)
				
	elif request_otp.validate_on_submit():
		response = resend_mail(app, session.get("recovery_email"))
		if isinstance(response, int):
			flash(f"Wait {response} before requesting for a new otp")
		else:
			response = Errors(error = str(response)).log()
			logging.error(response)
			flash("Something went wrong, try again later", "error")
	return render_template("change_password.html", form = form, request = request_otp)


@app.route("/email/change/request/", methods=["GET", "POST"])
@login_required
def request_email_change():
	user_id = session.get("id")
	form = VerifyPassword()
	if form.validate_on_submit():
		user_password = Users.fetch("password", user_id, "id")
		password = form.password.data.strip()
		try:
			if ph.verify(user_password, password):
				response = send_mail(app, session.get("new_email"))
				if response == "Email sent":
					return redirect(url_for("email_change")) 
				response = Errors(error = str(response), user_id = user_id).log()
				logging.error(response)
				flash("Something went wrong, try again later", "error")
				
		except VerifyMismatchError:
			form.password.errors.append("Incorrect Password")
	return render_template("email_change_request.html", form = form)
	
@app.route("/email/change/", methods=["GET", "POST"])
@login_required
def email_change():
	user_id = session.get("id")
	request_otp = RequestOTP()
	form = SignupPage2()
	if "new_email" not in session:
		return redirect(url_for("request_email_change"))
		
	if form.validate_on_submit():
		otp = form.otp.data
		response = verify_otp(otp)
		match (response):
			case "verified":
				Users.update_email(user_id, session.get("new_email"))
				session.pop("email", None)
				return redirect(url_for("profile"))
			case "incorrect":
				flash("Incorrect OTP, check and try again later", "error")
			case "invalid":
				flash("Invalid OTP, request a new one", "error")
			case _:
				flash("Something went wrong, try again later", "error")
				response = Errors(error = str(response)).log()
				logging.error(response)
	elif request_otp.validate_on_submit():
		response = resend_mail(app, session.get("new_email"))
		if isinstance(response, int):
			flash(f"Wait {response} before requesting for a new otp")
		else:
			response = Errors(error = str(response)).log()
			logging.error(response)
			flash("Something went wrong, try again later", "error")
			
	return render_template("signup(page_2).html",  form=form, request = request_otp, title = "Stratovault - Email Change")
		
@app.route("/upload/", methods = ["GET", "POST"])
@login_required
def upload():
	user_id = session.get("id")
	upload = FileUpload()
	folders = Uploads.fetch("folder", user_id, search = "user_id", all = True)
											
	if upload.validate_on_submit():
		file = upload.file.data
		mime_type = validate_mime(file)
		if not mime_type:
			mime = get_mime(file)
			flash("File type not supported", "error")
			return render_template(
														"upload.html", 
														upload = upload, 
														total_file_size = stringify_byte(session.get("total_file_size")), 
														folders = list(dict.fromkeys(folders))
													)
			
		folder = request.form.get("folder")
		file_name = add_extension(upload.filename.data.strip(), file.mimetype)
		if not file_name:
			file_name = file.filename
		file_name = file_name.replace("/", "-")
		file.seek(0, 2)
		file_size = file.tell()
		file.seek(0)
		file_data = Uploads(
												filename = file_name, 
												filesize = file_size,
												folder = folder,
												filelocation = "nill", 
												content_type = mime_type, 
												user_id = user_id
											)
		try:						
			if not file_data.save():
				flash("File already exists", "error")
				upload.filename.errors.append("Change File name ")
				return render_template(
															"upload.html", 
															upload = upload, 
															total_file_size = stringify_byte(session.get("total_file_size")), 
															folders = list(dict.fromkeys(folders))
														)
				
			file_location = f"{user_id}/{secure_filename(folder)}/{file_data.id}"
			file_data.filelocation = file_location
			db.session.commit()
			
			if not R2.upload(file, file_location):
				flash("Unable to connect to the cloud", "error")
				file_data.delete()
				return render_template(
															"upload.html", 
															upload = upload, 
															total_file_size = stringify_byte(session.get("total_file_size")), 
															folders = list(dict.fromkeys(folders))
														)
				
			session["total_file_size"] += file_size
			flash("Cloud upload successful", "success")
			
		except Exception as err:
				response = Errors(error = str(err), user_id = user_id).log()
				logging.error(response)
				flash("Something went wrong, please try again later", "error")
				
	return render_template(
												"upload.html", 
												upload = upload, 
												total_file_size = stringify_byte(session.get("total_file_size")), 
												folders = list(dict.fromkeys(folders))
											)
				
	
@app.route("/profile/", methods = ["GET", "POST"])
@login_required
def profile():
	user_id = session.get("id")	
	firstname = ChangeFirstname()
	lastname = ChangeLastname()
	email = ChangeEmail()
	user_detail = db.session.get(Users, user_id)
	
	if firstname.validate_on_submit():
		new_name = firstname.firstname.data.strip()
		if new_name != user_detail.firstname:
			try:
				response = Users.update_firstname(user_id, new_name)
				flash(response, "success")
			except Exception as err:
				response = Errors(error = str(err), user_id = user_id).log()
				logging.error(response)
				flash("Something went wrong, please try again later", "error")
				
	if lastname.validate_on_submit():
		new_name = lastname.lastname.data.strip()
		if new_name != user_detail.lastname:
			try:
				response = Users.update_lastname(user_id, new_name)
				flash(response, "success")
			except Exception as err:
				response = Errors(error = str(err), user_id = user_id).log()
				logging.error(response)
				flash("Something went wrong, try again later", "error")
				
	if email.validate_on_submit():
		new_email = email.email.data.strip().capitalize()
		if new_email != user_detail.email:
			email_exist = Users.fetch("email", new_email)
			if not email_exist:
				session["new_email"] = new_email
				return redirect(url_for("request_email_change"))
			flash("Email already in use", "error")
		
	firstname.firstname.data = user_detail.firstname
	lastname.lastname.data = user_detail.lastname
	email.email.data = user_detail.email
	
	if user_detail.has_profile_picture:
		profile_picture = R2.preview(f"profile_pictures/{user_id}", expiration = 30)
	else:
		profile_picture= url_for("static", filename = "image/logo.webp")
	
	return render_template(
												"profile.html", 
												firstname = firstname,
												lastname = lastname,
												email = email,
												profile_picture = profile_picture
											)

	
@app.get("/logout/")
@login_required
def logout():
	session.clear()
	return redirect(url_for("login"))