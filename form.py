from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField,BooleanField, SubmitField, IntegerField, ValidationError
from wtforms.validators import Length, DataRequired,Email, EqualTo, Regexp, InputRequired

def validate_length(form, field):
	if len(str(field.data)) != 6:
		raise ValidationError("OTP should be only 6 digits")

# class for login form
class LoginForm(FlaskForm):
	
	username = StringField("Username", validators = [DataRequired()])
	password = PasswordField("Password", validators = [DataRequired()])
	remember = BooleanField("Remember me")
	login = SubmitField("Login")
	

#class for signup form page 1
class SignupPage1(FlaskForm):
	first_name = StringField("First Name", validators = [DataRequired(), Length(min = 2, max = 60)])
	last_name = StringField("Last Name", validators = [DataRequired(), Length(min = 2, max = 60)])
	email = StringField("Email", validators = [DataRequired(),Email()])
	signup = SubmitField("Continue")

	
#class for signup from page 2	
class SignupPage2(FlaskForm):
	otp = IntegerField("OTP Code", validators = [InputRequired(), validate_length])
	submit = SubmitField("Verify")
	
#class for signup from page 3
class SignupPage3(FlaskForm):
	username = StringField("Username", validators = [DataRequired(), Length(min = 3, max = 20), Regexp(r"^[a-zA-Z](?:[a-zA-Z0-9]*(?:[-_][a-zA-Z0-9])?)*[a-zA-Z0-9]+$", message="Username can only contain alphanumeric characters with non-consecutive - or _")])	
	password = PasswordField("Password", validators = [DataRequired(), Length(min = 8)])
	c_password = PasswordField("Confirm Password", validators = [DataRequired(), Length(min = 8), EqualTo("password")])
	submit = SubmitField("Signup")
	

#class for form for uploading files
class FileUpload(FlaskForm):
	
	file = FileField("File upload", validators = [FileRequired(),FileAllowed(["jpg", "jpeg", "png", "gif", "webp", "pdf", "docx", "xlsx", "pptx", "txt", "mp4", "mov", "avi", "mkv", "mp3", "wav", "ogg", "zip", "rar", "7z", "tar.gz", "csv", "json"], "Filetype not supported, try putting it into a zip file then try again")])
	upload = SubmitField("Upload")