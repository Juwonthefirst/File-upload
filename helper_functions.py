import os, filetype, puremagic, random, uuid
from functools import wraps
from flask import session, request, redirect, url_for, flash, make_response
from flask_mail import Mail, Message
from datetime import datetime, timedelta, timezone
from redis import Redis, exceptions, ConnectionPool, SSLConnection

redis_pool = ConnectionPool(
							host = os.getenv("REDIS_HOST"), 
							password = os.getenv("REDIS_PASS"),
							port = 6379,
							connection_class = SSLConnection,
							max_connections = 10
							)
							
cache = Redis(connection_pool = redis_pool)


def stringify_byte(filesize):
	if filesize >= 900000:
		return f"{round(filesize/1000000, 2)} MB"
	elif 900 <=  filesize < 900000:
		return f"{round(filesize/1000, 2)} KB"
	elif filesize < 900:
		return f"{filesize} B"
		
def stringify_time(time):
	if time >= 3600:
		return f"{time // 3600} hours"
	elif 60 <= time < 3600:
		return f"{time // 60} minutes"
	elif time < 60:
		return f"{time} seconds"
		
def generate_anonymous_user_id():
	return "user_" + str(uuid.uuid4())
	
def create_response(body):
	response = make_response(body)
	response.set_cookie(
											"anonymous_user_id", 
											generate_anonymous_user_id(), 
											max_age = 60 * 60 * 24 * 365,
											httponly = True,
											secure = True,
											samesite = "Lax"
											)
	return response
				
#validating env
def validate_env(variables):
	for var in variables:
		if not os.getenv(var):
			raise RuntimeError(f"{var} is not set, check your enviroment variable")
			
# wrapper to restrict access to login necessary areas and enable cookies
def login_required(f):
	@wraps(f)
	def wrapped_function(*args, **kwargs):			
		if "id" not in session:
			session["next_page"] = request.url
			if "anonymous_user_id" not in request.cookies:
				return create_response(redirect(url_for("login")))			
			return redirect(url_for("login"))
				
		if "anonymous_user_id" not in request.cookies:
			return create_response(f(*args, **kwargs))
				
		return f(*args, **kwargs)
	return wrapped_function
	
	
#wrapper to redirect to current signup page and enable cookies
def not_logged_in(f):
	@wraps(f)
	def wrapped_function(*args, **kwargs):
		if "id" in session:
			if "anonymous_user_id" not in request.cookies:
				return create_response(redirect(url_for("home")))
			return redirect(url_for("home"))
			
		if "anonymous_user_id" not in request.cookies:
			return create_response(f(*args, **kwargs))
			
		return f(*args, **kwargs)
	return wrapped_function
	
#wrapper for enabling cookies on routes with no routes
def enable_cookies(f):
	@wraps(f)
	def wrapped_function(*args, **kwargs):
		if "anonymous_user_id" not in request.cookies:
			return create_response(f(*args, **kwargs))
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
	if mime:
		return mime
	for extension, mtype in extension_map.items():
		if file.filename.endswith(extension):
			return mtype
	return None
		
		
#validates if mime_type is allowed 
def validate_mime(file):
	allowed_mime = [
	"image/jpeg", "image/png", "image/gif", "image/webp",
	"application/pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	"application/vnd.openxmlformats-officedocument.presentationml.presentation",
	"text/plain", "video/mp4", "video/quicktime", "video/x-msvideo",
	"video/x-matroska", "audio/mpeg", "audio/wav","audio/wave", "audio/ogg",
	"application/zip", "application/vnd.rar", "application/x-7z-compressed",
	"application/gzip", "text/csv", "application/json"
]
	mime_type = get_mime(file)
	if mime_type in allowed_mime:
		return mime_type
	return None
		
#function generating a one time password
def get_otp():
	otp = random.randint(100000, 999999)
	cache.set(f"{request.cookies.get('anonymous_user_id')}:otp", otp)
	cache.expire(f"{request.cookies.get('anonymous_user_id')}:otp", 600)
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
	It will be invalid after 10 minutes	
	if you didn't make this request, You can ignore this email and take proper measures to properly secure your account
"""
		mail.send(message)
		flash("OTP sent successfully", "success")
		return "Email sent"
	except Exception as err:
		flash("Something went wrong, try again later", "error")
		return err


def verify_otp(otp):
	try:
		if cache.exists(f"{request.cookies.get('anonymous_user_id')}:otp"):
			stored_otp = int(cache.get(f"{request.cookies.get('anonymous_user_id')}:otp").decode())
			if otp == stored_otp:
				cache.delete(f"{request.cookies.get('anonymous_user_id')}:otp")
				return "verified"
			return "incorrect"
		return "invalid"
	except Exception as err:
		return err
		
def resend_mail(app):
	otp_time_to_live = cache.ttl(f"{request.cookies.get('anonymous_user_id')}:otp")
	
	if otp_time_to_live > 480:
		response = stringify_time(otp_time_to_live - 480)
	else:
		response = send_mail(app, session.get("email"))
	return response
		
def add_extension(filename, mime_type):
	if not filename:
		return None
	extensions = {
	 "image/jpeg" :".jpg", "image/png": ".png", "image/gif": ".gif", "image/webp": ".webp",
	 "application/pdf": ".pdf","application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
	"text/plain": ".txt", "video/mp4": ".mp4", "video/quicktime": ".mov", "video/x-msvideo": ".avi",
		"video/x-matroska": ".mkv", "audio/mpeg": ".mp3", "audio/wav": ".wav", "audio/wave": ".wav", "audio/ogg":  ".ogg",
	 "application/zip": ".zip", "application/vnd.rar": ".rar", "application/x-7z-compressed": ".7z",
	"application/gzip": ".tar.gz", "text/csv": ".csv", "application/json": ".json"
}
	return filename + extensions[mime_type]