from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField,BooleanField, SubmitField
from wtforms.validators import Length, DataRequired,Email, EqualTo



class LoginForm(FlaskForm):
	
	username = StringField("Username", validators = [DataRequired(), Length(min = 3, max = 20)])
	password = PasswordField("Password", validators = [DataRequired(), Length(min = 8)])
	remember = BooleanField("Remember me")
	login = SubmitField("Login")
	
class SignupForm(FlaskForm):
	
	username = StringField("Username", validators = [DataRequired(), Length(min = 3, max = 20)])
	email = StringField("Email", validators = [DataRequired(),Email()])
	password = PasswordField("Password", validators = [DataRequired(), Length(min = 8)])
	c_password = PasswordField("Confirm Password", validators = [DataRequired(), Length(min = 8), EqualTo("password")])
	signup = SubmitField("Sign Up")
	
	
class FileUpload(FlaskForm):
	
	file = FileField("File upload", validators = [FileRequired(),FileAllowed(["jpg", "png", "gif", "webp", "svg", "pdf", "docx", "xlsx", "pptx", "txt", "mp4", "mov", "avi", "mkv", "mp3", "wav", "ogg", "zip", "rar", "7z", "tar.gz"], "Filetype not supported, try putting it into a zip file then try again")])
	upload = SubmitField("Upload")