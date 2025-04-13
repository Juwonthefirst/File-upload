import os, filetype, puremagic
from functools import wraps
from flask import session, request, redirect, url_for, flash
from flask_mail import Mail, Message
from datetime import datetime, timedelta, timezone
import random, gzip, json, base64

#validating env
def validate_env(variables):
	for var in variables:
		if not os.getenv(var):
			raise RuntimeError(f"{var} is not set, check your enviroment variable")
			
# wrapper to restrict access to login necessary areas
def login_required(f):
	@wraps(f)
	def wrapped_function(*args, **kwargs):
		if "id" not in session:
			session["next_page"] = request.url
			return redirect(url_for("login"))
		return f(*args, **kwargs)
	return wrapped_function
	
	
#wrapper to redirect to current signup page
def not_logged_in(f):
	@wraps(f)
	def wrapped_function(*args, **kwargs):
		if "id" in session:
			return redirect(url_for("home"))
		return f(*args, **kwargs)
	return wrapped_function
	
#get mime from filetype
def get_filetype_mimetype(file):
	try:
		return filetype.guess(file).mime
	except AttributeError:
		return None

#get mime from puremagic
def get_puremagic_mimetype(file):
	try:
		return puremagic.from_stream(file, mime = True)
	except puremagic.main.PureError:
		return None

#get accurate mimetype
def get_mime(file):
	extension_map = {".csv" : "text/csv", ".txt" : "text/plain"}
	mime = get_puremagic_mimetype(file) or get_filetype_mimetype(file)
	if not mime:
		for ext, mtype in extension_map.items():
			if file.filename.endswith(ext):
				return mtype
		return None
	return mime
		
		
#validates if mime_type is allowed 
def validate_mime(file):
	allowed_mime = [
	"image/jpeg", "image/png", "image/gif", "image/webp",
	"application/pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	"application/vnd.openxmlformats-officedocument.presentationml.presentation",
	"text/plain", "video/mp4", "video/quicktime", "video/x-msvideo",
	"video/x-matroska", "audio/mpeg", "audio/wav", "audio/ogg",
	"application/zip", "application/vnd.rar", "application/x-7z-compressed",
	"application/gzip", "text/csv", "application/json"
]
	mime_type = get_mime(file)
	if mime_type in allowed_mime:
		return mime_type
	else:
		return None
		
#function generating a one time password
def get_otp():
	otp = random.randint(100000, 999999)
	session["otp"] = {
									"code": otp,
									 "expires_in": datetime.now(timezone.utc) + timedelta(minutes = 10) 
								}
	return otp

#function for sending mail through flask-mail	
def send_mail(app, receiver):
	try:
		mail = Mail(app)
		otp = get_otp()
		message = Message(
												subject = "OTP request ",
												recipients = [ receiver ]
											)
		message.body = f"""
	Here is your one time password {otp}	
	if you didn't make this request, You can ignore this email and take proper measures to properly secure your account
"""
		mail.send(message)
		return "Email sent"
	except Exception as err:
		flash("Something went wrong, try again later", "error")
		return err


def verify_otp(otp):
	try:
		current_time = datetime.now(timezone.utc)
		print(current_time.tzinfo)
		stored_otp = session.get("otp")
		stored_otp_code = stored_otp.get("code")
		otp_expiration_time = stored_otp.get("expires_in")
		if otp == stored_otp_code:
			session.pop("otp", None)
			if current_time <= otp_expiration_time:
				return "verified"
			return "expired"
		return "invalid"
	except Exception as err:
		return err
		
def resend_mail(app):
	if "otp" in session:
		request_time = session["otp"]["expires_in"] - timedelta(minutes = 10)
		current_time = datetime.now(timezone.utc)
		if current_time >= request_time + timedelta(minutes = 2):
			response = send_mail(app, session.get("email"))
			if response == "Email sent":
				flash("New OTP sent successfully", "success")
			else:	
				flash("Something went wrong, try again later", "error")
		else:
			response = "Wait two minutes before requesting for a new otp"
			flash(response, "success")
	else:
		response = send_mail(app, session.get("email"))
		if response == "Email sent":
			flash("New OTP sent successfully", "success")
		else:
			flash("Something went wrong, try again later", "error")
	return response
	
def stringify_byte(filesize):
	if filesize >= 900000:
		return f"{round(filesize/1000000, 2)} MB"
	elif 900 <=  filesize < 900000:
		return f"{round(filesize/1000, 2)} KB"
	elif filesize < 900:
		return f"{filesize} B"

def add_extension(filename, mime_type):
	if not filename:
		return None
	extensions = {
	 "image/jpeg" :".jpg", "image/png": ".png", "image/gif": ".gif", "image/webp": ".webp",
	 "application/pdf": ".pdf","application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
	"text/plain": ".txt", "video/mp4": ".mp4", "video/quicktime": ".mov", "video/x-msvideo": ".avi",
		"video/x-matroska": ".mkv", "audio/mpeg": ".mp3", "audio/wav": ".wav","audio/ogg":  ".ogg",
	 "application/zip": ".zip", "application/vnd.rar": ".rar", "application/x-7z-compressed": ".7z",
	"application/gzip": ".tar.gz", "text/csv": ".csv", "application/json": ".json"
}
	return filename + extensions[mime_type]