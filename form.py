from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField,BooleanField, SubmitField
from wtforms.validators import Length, DataRequired,Email, EqualTo, Regexp


# class for login form
class LoginForm(FlaskForm):
	
	username = StringField("Username", validators = [DataRequired()])
	password = PasswordField("Password", validators = [DataRequired()])
	remember = BooleanField("Remember me")
	login = SubmitField("Login")
	

#class for signup form
class SignupForm(FlaskForm):
	
	username = StringField("Username", validators = [DataRequired(), Length(min = 3, max = 20), Regexp(r"^[a-zA-Z](?:[a-zA-Z0-9]*(?:[-_][a-zA-Z0-9])?)*[a-zA-Z0-9]+$", message="Username can only contain alphanumeric characters with non-consecutive - or _")])
	email = StringField("Email", validators = [DataRequired(),Email()])
	password = PasswordField("Password", validators = [DataRequired(), Length(min = 8)])
	c_password = PasswordField("Confirm Password", validators = [DataRequired(), Length(min = 8), EqualTo("password")])
	signup = SubmitField("Sign Up")
	
	
	
#class for form for uploading files
class FileUpload(FlaskForm):
	
	file = FileField("File upload", validators = [FileRequired(),FileAllowed(["jpg", "png", "gif", "webp", "svg", "pdf", "docx", "xlsx", "pptx", "txt", "mp4", "mov", "avi", "mkv", "mp3", "wav", "ogg", "zip", "rar", "7z", "tar.gz"], "Filetype not supported, try putting it into a zip file then try again")])
	upload = SubmitField("Upload")
	
	
#class for form for uploading files
class FileRetrieve(FlaskForm):
	pass