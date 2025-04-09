from flask import Flask, request, render_template, redirect, url_for, flash, session, send_file
from werkzeug.utils import secure_filename
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
from dotenv import load_dotenv
from MyDBAlchemy import db, Users, Uploads, Errors, init_table
from helper_functions import (
														login_required, 
														validate_mime, 
														send_mail, 
														verify_otp, 
														not_logged_in, 
														resend_mail,
														stringify_byte
													)
from R2_manager import R2
from io import BytesIO
import jwt

# flask configuration settings
app=Flask(__name__)
app.config.from_pyfile("config.py")
app.permanent_session_lifetime = timedelta(days=30)

#initializing other modules
db.init_app(app)
init_table(app)
ph = PasswordHasher()
jwt_key = app.config.get("SECRET_KEY")
				
				
# routing function
# add username/email login by accepting text then checking if its exists in the username or email database
@app.route("/login", methods = ["GET", "POST"])
@not_logged_in
def login():
	try:				
		next_page = session.get("next_page")
		form = LoginForm()
		if form.validate_on_submit():
			detail = form.username.data.capitalize().strip()
			password = form.password.data.strip()
			user_info = Users.fetch_user_row(detail)
			if user_info:
				try:
					if ph.verify(user_info.password, password):
						file_sizes = Uploads.fetch("filesize", user_info.id, search = "user_id", all = True)
						session.pop("next_page", None)
						session.permanent = True
						session.update({
												"id": user_info.id,
												"username": user_info.username,
												"total_file_size": sum(file_sizes)
												})
						return redirect( next_page or url_for("home"))
				except VerifyMismatchError:
					flash("incorrect username and password combination", "error")
			else:
				flash("incorrect username and password combination", "error")
	except Exception as err:
		Errors(error = str(err)).log()			
	return render_template("login.html", form=form)


@app.route("/signup/user-info", methods = ["GET", "POST"])
@not_logged_in
def signup1():
				
	form = SignupPage1()
	if form.validate_on_submit():
		first_name = form.first_name.data.strip().capitalize()
		last_name = form.last_name.data.strip().capitalize()
		email = form.email.data.strip().capitalize()
		email_exist = Users.fetch("email", email)
		if not email_exist:
			session.permanent = True
			session.update({
											"first_name": first_name,
											"last_name": last_name,
											"email": email
											})
			response = send_mail(app, email)
			if response == "Email sent":
				return redirect(url_for("signup2"))
			Errors(error = str(response)).log()
		else:
			form.email.errors.append("Email already in use")
	return render_template("signup(page_1).html",  form=form)
				
			
@app.route("/signup/verify", methods = ["GET", "POST"])
@not_logged_in
def signup2():
	
	if "email" not in session:
		return redirect(url_for("signup1"))
	
	request = RequestOTP()
	form = SignupPage2()
	if request.validate_on_submit():
		response = resend_mail(app)
		if response != "Email sent":
			Errors(error = str(response)).log
	elif form.validate_on_submit():
		otp = form.otp.data
		response = verify_otp(otp)
		match (response):
			case "verified":
				session["email_verified"] = True
				return redirect(url_for("signup3"))
			case "expired":
				flash("Expired OTP, request a new one", "error")
			case "invalid":
				flash("Invalid OTP, check and try again later", "error")
			case _:
				flash("Something went wrong, try again later", "error")
				Errors(error = str(response)).log()
		
	return render_template("signup(page_2).html",  form=form, request = request, title = "Stratovault - verify OTP")

@app.route("/signup/finish", methods = ["GET", "POST"])
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
		if not username_exist:
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
					form.username.errors.append("Unknown error, Try logging in")
				else:
					session.clear()
					session.permanent = True
					session.update({
													"id" : new_user.id,
													"username" : username, 
													"total_file_size": 0
													})
					return redirect(next_page or url_for("home"))
			except Exception as err:
				print(err)
				Errors(error = str(err)).log()
				flash("Something went wrong, please try again", "error")
		else:
			form.username.errors.append("Username already in use")
			
	return render_template("signup(page_3).html",  form=form)
	

@app.get("/")
@login_required
def home():
	user_id = session.get("id")												
	folders = Uploads.fetch("folder", user_id, search = "user_id", all = True)
	return render_template("home.html", folders = list(dict.fromkeys(folders)), heading = "Stratovault")
	

@app.get("/cloud/<string:folder>")
@login_required
def cloud(folder):
	user_id = session.get("id")
	files = Uploads.fetch_filename(user_id, folder, all = True)
	return render_template("home.html", files=list(dict.fromkeys(files)), heading = folder, folder = folder)
	
# route for downloading files
@app.get("/cloud/<string:folder>/<string:filename>/download")
@login_required
def download(folder, filename):
	user_id = session.get("id")
	file_row = Uploads.fetch_filerow(user_id, folder, filename)	
	file_location = file_row.filelocation
	try:
		response = R2.get_file(file_location)
	except Exception as err:
		Errors(error = str(err), user_id = session.get("id")).log()
		flash("Something went wrong, please try again later", "error")
		return redirect(url_for("cloud", folder = folder))
		
	if  response == "File not found":
		flash("File not found", "error")
		return redirect(url_for("cloud", folder = folder))
	return send_file (
		BytesIO(response),
		download_name = filename,
		as_attachment = True
		)
	
@app.route("/cloud/<string:folder>/<string:filename>/delete", methods = ["GET", "POST"])
@login_required
def delete(folder, filename):
	user_id = session.get("id")
	form = ConfirmDelete()
	if form.validate_on_submit():
		file_row = Uploads.fetch_filerow(user_id, folder, filename)	
		file_location = file_row.filelocation
		try:
			if R2.delete(file_location):
				file_row.delete()
				flash(f"{filename} removed from your cloud", "success")
				return redirect(url_for("cloud", folder = folder))
				
			else:
				flash("Unable to connect to your cloud", "error")
				return redirect(url_for("cloud", folder = folder))
					
		except Exception as err:
			Errors(error = str(err), user_id = user_id).log()
			
		flash("Unable to connect to your cloud", "error")
		return redirect(url_for("cloud", folder = folder))
		
	return render_template("confirm.html", form = form, filename = filename)
	
	
@app.get("/cloud/<string:folder>/<string:filename>/preview")
@login_required
def preview(folder, filename):	
	try:
		allowed_mime = ["image", "video", "audio"]
		user_id = session.get("id")
		file_row = Uploads.fetch_filerow(user_id, folder, filename)
		file_type = file_row.content_type
		file_location = file_row.filelocation
		for mime in allowed_mime:
			if file_type.startswith(mime):
				url = R2.preview(file_location, 3600)
				if url:
					return render_template ("preview.html", type = mime,url = url)
				else:
					flash("Unable to connect to your cloud", "error")
					return redirect(url_for("cloud", folder = folder))
		flash("Can only preview Images, Videos or Audio", "error")
	except Exception as err:
		Errors(error = str(err), user_id = user_id).log()
		flash("Something went wrong, Please try again later", "error")
	
	return redirect(url_for("cloud", folder = folder))	
	
@app.route("/cloud/<string:folder>/<string:filename>/share", methods = ["GET", "POST"])
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
		file_location = file_row.filelocation
		file_size = file_row.filesize
		file_type = file_row.content_type
		token = jwt.encode(
				{
					"name": user_firstname,
					"filename" : filename,
					"filesize": file_size, 
					"filelocation" : file_location,
					"filetype": file_type,
					"recipients":  recievers,
					"exp" : datetime.now(timezone.utc) + timedelta(hours = 1) 
				},
				 jwt_key,
				 algorithm = "HS256"
			)
		share_link = url_for("shared", token = token, _external = True)
		print(share_link)
	return render_template("cloud_share.html", link = share_link, filename = file_row.filename, filesize = stringify_byte(file_row.filesize), form = form)


@app.route("/shared/<token>", methods = ["GET", "POST"])
def shared(token):
	user_id = session.get("id")
	username = session.get("username")
	form = SharedFileDownload()
	if form.validate_on_submit():
		try:
			response = R2.get_file(session.get("filelocation"))
			file_name = session.get("filename")
			session.pop("filelocation", None)
			session.pop("filename", None)
		except Exception as err:
			Errors(error = str(err), user_id = session.get("id")).log()
			flash("Something went wrong, please try again later", "error")
			return redirect(url_for("cloud", folder = folder))
		
		if  response == "File not found":
			flash("File not found", "error")
			return redirect(url_for("cloud", folder = folder))
			
		elif response is None:
			flash("Unable to connect to your cloud", "error")
			return redirect(url_for("cloud", folder = folder))
			
		return send_file(
										BytesIO(response),
										download_name = file_name,
										as_attachment = True
									)
									
	try:
		file_data = jwt.decode(token, jwt_key, algorithms = "HS256")
	except jwt.ExpiredSignatureError:
		return render_template("Shared.html", error = "Expired Link")
	except jwt.InvalidTokenError:
		return render_template("Shared.html", error = "Invalid Link")
	except Exception as err:
		Errors(error = str(err), user_id = user_id).log()		
	receivers_list = file_data.get("recipients")
	if username in receivers_list or receivers_list == ["All"]:
		previewable_mime = ["image/jpeg", "image/png", "image/gif", "image/webp",  "video/mp4", "video/quicktime", "video/x-msvideo","video/x-matroska", "audio/mpeg", "audio/wav", "audio/ogg"]
		file_type = file_data.get("filetype")
		file_size = file_data.get("filesize")
		sender_name = file_data.get("name")
		file_name = file_data.get("filename")
		file_location = file_data.get("filelocation")
		if file_type in previewable_mime:
			url = R2.preview(file_location, 3600)
		else:
			url = "Not previewable"
		session["filelocation"] = file_location
		session["filename"] = file_name
		return render_template("Shared.html", filename = file_name, filesize = stringify_byte(file_size), filetype = file_type, sender = sender_name, url = url, form = form)
	return render_template("Shared.html", error = "Access Denied")


@app.route("/password/change/request", methods = ["GET", "POST"])
def request_password_change():
	form = RequestChangePass()
	if form.validate_on_submit():
		detail = form.detail.data.strip().capitalize()
		user_info = Users.fetch_user_row(detail)
		if user_info:
			response = send_mail(app, user_info.email)
			if response == "Email sent":
				session["id"] = user_info.id
				session["email"] = user_info.email
				return redirect(url_for("change_password"))
		else:
			flash("User doesn't exist", "error")
	return render_template("request_password_change.html", form = form)
	

@app.route("/password/change", methods = ["GET", "POST"])
#@login_required
def change_password():
	user_id = session.get("id")
	form = ChangePass()
	request = RequestOTP()
	if "otp" not in session:
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
			case "expired":
				flash("Expired OTP, request a new one", "error")
			case "invalid":
				flash("Invalid OTP, check and try again later", "error")
			case _:
				flash("Something went wrong, try again later", "error")
				Errors(error = str(response)).log()
	elif request.validate_on_submit():
		response = resend_mail(app)
		if response != "Email sent":
			Errors(error = str(response)).log
				
	return render_template("change_password.html", form = form, request = request)


@app.route("/email/change/request", methods=["GET", "POST"])
@login_required
def request_email_change():
	user_id = session.get("id")
	form = VerifyPassword()
	if form.validate_on_submit():
		user_details = db.session.get(Users, user_id)
		password = form.password.data.strip()
		try:
			if ph.verify(user_details.password, password):
				response = send_mail(app, session.get("email"))
				if response == "Email sent":
					return redirect(url_for("email_change")) 
				Errors(error = str(response), user_id = user_id).log()
		except VerifyMismatchError:
			form.password.errors.append("Incorrect Password")
	return render_template("email_change_request.html", form = form)
	
@app.route("/email/change", methods=["GET", "POST"])
@login_required
def email_change():
	user_id = session.get("id")
	request = RequestOTP()
	form = SignupPage2()
	if "otp" not in session:
		return redirect(url_for("request_email_change"))
	if form.validate_on_submit():
		otp = form.otp.data
		response = verify_otp(otp)
		match (response):
			case "verified":
				Users.update_email(user_id, session.get("email"))
				session.pop("email", None)
				return redirect(url_for("profile"))
			case "expired":
				flash("Expired OTP, request a new one", "error")
			case "invalid":
				flash("Invalid OTP, check and try again later", "error")
			case _:
				flash("Something went wrong, try again later", "error")
				Errors(error = str(response)).log()
	elif request.validate_on_submit():
		response = resend_mail(app)
		if response != "Email sent":
			Errors(error = str(response)).log
		
	return render_template("signup(page_2).html",  form=form, request = request, title = "Stratovault - Email Change")
		
@app.route("/upload", methods = ["GET", "POST"])
@login_required
def upload():
	user_id = session.get("id")
	username = session.get("id")
	upload = FileUpload()
	file = upload.file.data
	if upload.validate_on_submit():
		file = upload.file.data
		mime_type = validate_mime(file)
		if mime_type:
			folder = request.form.get("folder").strip()
			file_name = file.filename
			file_size = len(file.read())
			file.seek(0)
			file_data = Uploads(
													filename = file_name, 
													filesize = file_size,
													folder = folder,
													filelocation = "nill", 
													content_type = mime_type, 
													user_id = user_id
												)
			file_data.save()
			file_location = f"{user_id}/{folder}/{file_data.id}"
			file_data.filelocation = file_location
			db.session.commit()
			try:
				if R2.upload(file, file_location):
					session["total_file_size"] += file_size
					flash("Cloud upload successful", "success")
				else:
					flash("Unable to connect to the cloud", "error")
					#file_data.delete()
			except Exception as err:
				Errors(error = str(err), user_id = user_id).log()
				flash("Something went wrong, please try again later", "error")
		else:
			flash("File type not supported", "error")
			
	folders = Uploads.fetch("folder", user_id, search = "user_id", all = True)			
	return render_template("upload.html", upload = upload, total_file_size = stringify_byte(session.get("total_file_size")), folders = list(dict.fromkeys(folders)))
	
@app.route("/profile", methods = ["GET", "POST"])
@login_required
def profile():
	user_id = session.get("id")	
	firstname = ChangeFirstname()
	lastname = ChangeLastname()
	email = ChangeEmail()
	if firstname.validate_on_submit():
		new_name = firstname.firstname.data
		try:
			response = Users.update_firstname(user_id, new_name)
			flash(response, "success")
		except Exception as err:
			Errors(error = str(err), user_id = user_id).log()
			flash("Something went wrong, please try again later", "error")
			
	if lastname.validate_on_submit():
		new_name = lastname.lastname.data
		try:
			response = Users.update_lastname(user_id, new_name)
			flash(response, "success")
		except Exception as err:
			Errors(error = str(err), user_id = user_id).log()
			flash("Something went wrong, please try again later", "error")
	if email.validate_on_submit():
		session["email"] = email.email.data.strip().capitalize()
		return redirect(url_for("request_email_change"))
		
	user_detail = db.session.get(Users, user_id)	
	firstname.firstname.data = user_detail.firstname
	lastname.lastname.data = user_detail.lastname
	email.email.data = user_detail.email
	
	return render_template("profile.html", firstname = firstname, lastname = lastname, email = email)

@app.get("/session")
#@login_required
def sessions():
	return dict(session)
	
@app.route("/logout")
@login_required
def logout():
	session.clear()
	return redirect(url_for("login"))
		
app.run(debug = True, host = "0.0.0.0", port = 5000)