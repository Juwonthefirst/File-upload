import os, filetype, puremagic
from functools import wraps
from flask import session, request, redirect, url_for

#validating env
def validate_env():
	variables = ["SECRET_KEY", "DATABASE_URL"]
	for var in variables:
		if not os.getenv(var):
			raise RuntimeError(f"{var} is not set, check your enviroment variable")
			
# wrapper to restrict access to login necessary areas
def login_required(f):
	@wraps(f)
	def wrapped_function(*args, **kwargs):
		if "username" not in session:
			session["next_page"] = request.url
			return redirect(url_for("login"))
		return f(*args, **kwargs)
	return wrapped_function
	
#get mime from puremagic
def get_filetype_mimetype(file):
	try:
		return filetype.guess(file).mime
	except AttributeError:
		return None

#get mime from puremagic
def get_puremagic_mimetype(file):
	try:
		return puremagic.from_stream(file, mime = True) or None
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