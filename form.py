from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, PasswordField,BooleanField, SubmitField
from wtforms.validators import Length, DataRequired,Email, Equalto


class LoginForm(FlaskForm):
	
	username = StringField("Username", validators = [DataRequired(), Length(min = 3, max = 20)])
	password = PasswordField("Password", validators = [DataRequired(), Length(min = 8)])
	remember = BooleanField("Remember me")
	login = SubmitField("Login")
	
class SignupForm(FlaskForm):
	
	username = StringField("Username", validators = [DataRequired(), Length(min = 3, max = 20)])
	email = StringField("Email", validators = [DataRequired(),Email()])
	password = PasswordField("Password", validators = [DataRequired(), Length(min = 8)])
	c_password = PasswordField("Confirm Password", validators = [DataRequired(), Length(min = 8), Equalto("password")])
	signup = SubmitField("Sign Up")
	
	
class FileUpload(FlaskForm):
	
	file = FileField("File upload", validators = [FileRequired()])
	upload = SubmitField("Upload")